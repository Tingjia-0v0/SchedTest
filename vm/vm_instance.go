package vm

import (
	"context"
	"fmt"
	"os"
	"schedtest/pkg/report"
	"schedtest/vm/qemu"
	"sync"
	"time"
)

type InstanceState int
type UpdateInfo func(cb func(info *Info))
type Runner func(ctx context.Context, inst *Instance, updInfo UpdateInfo)

const (
	StateOffline InstanceState = iota
	StateBooting
	StateWaiting
	StateRunning
)

type Info struct {
	State      InstanceState
	Status     string
	LastUpdate time.Time
}

type Instance struct {
	pool          *Pool
	qemuimpl      *qemu.Instance
	workdir       string
	index         int
	snapshotSetup bool
	onClose       func()

	mu   sync.Mutex
	info Info

	job         Runner
	switchToJob chan Runner
	stop        func()
}

func (inst *Instance) Copy(hostSrc string) (string, error) {
	return inst.qemuimpl.Copy(hostSrc)
}

func (inst *Instance) Forward(port int) (string, error) {
	return inst.qemuimpl.Forward(port)
}

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

func (inst *Instance) MachineInfo() ([]byte, error) {
	return inst.qemuimpl.MachineInfo()
}

func (inst *Instance) Diagnose(rep *report.Report) []byte {
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

func (pi *Instance) reset(stop func()) {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	pi.info = Info{
		State:      StateOffline,
		LastUpdate: time.Now(),
	}
	pi.stop = stop
	pi.switchToJob = make(chan Runner)
}

func (pi *Instance) updateInfo(upd func(*Info)) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	upd(&pi.info)
	pi.info.LastUpdate = time.Now()
}

func (pi *Instance) status(status InstanceState) {
	pi.updateInfo(func(info *Info) {
		info.State = status
	})
}

func (pi *Instance) getInfo() Info {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return pi.info
}

func (pi *Instance) free(job Runner) {
	pi.mu.Lock()
	if pi.job != nil {
		// A change of a default job, let's force restart the instance.
		pi.stop()
	}
	pi.job = job
	switchToJob := pi.switchToJob
	pi.mu.Unlock()

	select {
	case switchToJob <- job:
		// Just in case the instance has been waiting.
		return
	default:
	}
}

var beforeContextDefault = 128 << 10
