// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vm provides an abstract test machine (VM, physical machine, etc)
// interface for the rest of the system.
// For convenience test machines are subsequently collectively called VMs.
// Package wraps vmimpl package interface with some common functionality
// and higher-level interface.
package vm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"schedtest/pkg/log"
	"schedtest/pkg/mgrconfig"
	"schedtest/pkg/osutil"
	"schedtest/pkg/report"
	"schedtest/pkg/stat"
	"schedtest/sys/targets"
	"schedtest/vm/dispatcher"
	"schedtest/vm/qemu"
	"schedtest/vm/vmimpl"
)

type Pool struct {
	qemuimpl           *qemu.Pool
	workdir            string
	timeouts           targets.Timeouts
	count              int
	activeCount        int32
	statOutputReceived *stat.Val
}

type Instance struct {
	pool          *Pool
	qemuimpl      *qemu.Instance
	workdir       string
	index         int
	snapshotSetup bool
	onClose       func()
}

var (
	Shutdown                = vmimpl.Shutdown
	ErrTimeout              = vmimpl.ErrTimeout
	_          BootErrorer  = vmimpl.BootError{}
	_          InfraErrorer = vmimpl.InfraError{}
)

func ShutdownCtx() context.Context {
	ctx, done := context.WithCancel(context.Background())
	go func() {
		<-Shutdown
		done()
	}()
	return ctx
}

type BootErrorer interface {
	BootError() (string, []byte)
}

type InfraErrorer interface {
	InfraError() (string, []byte)
}

// vmType splits the VM type from any suffix (separated by ":"). This is mostly
// useful for the "proxyapp" type, where pkg/build needs to specify/handle
// sub-types.
func vmType(fullName string) string {
	name, _, _ := strings.Cut(fullName, ":")
	return name
}

// Create creates a VM pool that can be used to create individual VMs.
func Create(cfg *mgrconfig.Config, debug bool) (*Pool, error) {
	env := &vmimpl.Env{
		OS:       cfg.TargetOS,
		Arch:     cfg.TargetVMArch,
		Workdir:  cfg.Workdir,
		Image:    cfg.Image,
		SSHKey:   cfg.SSHKey,
		SSHUser:  cfg.SSHUser,
		Timeouts: cfg.Timeouts,
		Debug:    debug,
	}
	impl, err := qemu.Ctor(env)
	if err != nil {
		return nil, err
	}
	count := impl.Count()
	if debug && count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", count)
		count = 1
	}

	return &Pool{
		qemuimpl: impl,
		workdir:  env.Workdir,
		timeouts: cfg.Timeouts,
		count:    count,
		statOutputReceived: stat.New("vm output", "Bytes of VM console output received",
			stat.Graph("traffic"), stat.Rate{}, stat.FormatMB),
	}, nil
}

func (pool *Pool) Count() int {
	return pool.count
}

func (pool *Pool) Create(index int) (*Instance, error) {
	if index < 0 || index >= pool.count {
		return nil, fmt.Errorf("invalid VM index %v (count %v)", index, pool.count)
	}
	workdir, err := osutil.ProcessTempDir(pool.workdir)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance temp dir: %w", err)
	}

	impl, err := pool.qemuimpl.Create(workdir, index)
	if err != nil {
		os.RemoveAll(workdir)
		return nil, err
	}
	atomic.AddInt32(&pool.activeCount, 1)
	return &Instance{
		pool:     pool,
		qemuimpl: impl,
		workdir:  workdir,
		index:    index,
		onClose:  func() { atomic.AddInt32(&pool.activeCount, -1) },
	}, nil
}

// TODO: Integration or end-to-end testing is needed.
//
//	https://github.com/google/syzkaller/pull/3269#discussion_r967650801
func (pool *Pool) Close() error {
	if pool.activeCount != 0 {
		panic("all the instances should be closed before pool.Close()")
	}
	return nil
}

func (inst *Instance) Copy(hostSrc string) (string, error) {
	return inst.qemuimpl.Copy(hostSrc)
}

func (inst *Instance) Forward(port int) (string, error) {
	return inst.qemuimpl.Forward(port)
}

type ExitCondition int

const (
	// The program is allowed to exit after timeout.
	ExitTimeout = ExitCondition(1 << iota)
	// The program is allowed to exit with no errors.
	ExitNormal
	// The program is allowed to exit with errors.
	ExitError
)

type InjectExecuting <-chan bool
type OutputSize int

// An early notification that the command has finished / VM crashed.
type EarlyFinishCb func()

// Run runs cmd inside of the VM (think of ssh cmd) and monitors command execution
// and the kernel console output. It detects kernel oopses in output, lost connections, hangs, etc.
// Returns command+kernel output and a non-symbolized crash report (nil if no error happens).
// Accepted options:
//   - ExitCondition: says which exit modes should be considered as errors/OK
//   - OutputSize: how much output to keep/return
func (inst *Instance) Run(ctx context.Context, reporter *report.Reporter, command string, opts ...any) (
	[]byte, *report.Report, error) {
	exit := ExitNormal
	var injected <-chan bool
	var finished func()
	outputSize := beforeContextDefault
	for _, o := range opts {
		switch opt := o.(type) {
		case ExitCondition:
			exit = opt
		case OutputSize:
			outputSize = int(opt)
		case InjectExecuting:
			injected = opt
		case EarlyFinishCb:
			finished = opt
		default:
			panic(fmt.Sprintf("unknown option %#v", opt))
		}
	}
	outc, errc, err := inst.qemuimpl.Run(ctx, command)
	if err != nil {
		return nil, nil, err
	}
	mon := &monitor{
		inst:            inst,
		outc:            outc,
		injected:        injected,
		errc:            errc,
		finished:        finished,
		reporter:        reporter,
		beforeContext:   outputSize,
		exit:            exit,
		lastExecuteTime: time.Now(),
	}
	rep := mon.monitorExecution()
	return mon.output, rep, nil
}

func (inst *Instance) Info() ([]byte, error) {
	return inst.qemuimpl.Info()
}

func (inst *Instance) diagnose(rep *report.Report) []byte {
	if rep == nil {
		panic("rep is nil")
	}
	return inst.qemuimpl.Diagnose(rep)
}

func (inst *Instance) Index() int {
	return inst.index
}

func (inst *Instance) Close() error {
	err := inst.qemuimpl.Close()
	if retErr := os.RemoveAll(inst.workdir); err == nil {
		err = retErr
	}
	inst.onClose()
	return err
}

type Dispatcher = dispatcher.Pool[*Instance]

func NewDispatcher(pool *Pool, def dispatcher.Runner[*Instance]) *Dispatcher {
	return dispatcher.NewPool(pool.count, pool.Create, def)
}

const (
	maxErrorLength = 256

	lostConnectionCrash  = "lost connection to test machine"
	noOutputCrash        = "no output from test machine"
	timeoutCrash         = "timed out"
	executorPreemptedStr = "SYZ-EXECUTOR: PREEMPTED"
	vmDiagnosisStart     = "\nVM DIAGNOSIS:\n"
)

var (
	executingProgram = []byte("executed programs:") // syz-execprog output

	beforeContextDefault = 128 << 10
	afterContext         = 128 << 10

	tickerPeriod = 10 * time.Second
)
