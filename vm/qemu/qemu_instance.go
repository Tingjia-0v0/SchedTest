// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"schedtest/pkg/log"
	"schedtest/pkg/osutil"
	"schedtest/sys/targets"
	"schedtest/vm/vmimpl"

	"schedtest/pkg/report"

	"github.com/google/uuid"
)

type Instance struct {
	index    int
	cfg      *Config
	target   *targets.Target
	version  string
	image    string
	os       string
	timeouts targets.Timeouts
	workdir  string
	vmimpl.SSHOptions
	debug bool

	rpipe io.ReadCloser
	wpipe io.WriteCloser

	args        []string
	monport     int
	forwardPort int
	mon         net.Conn
	monEnc      *json.Encoder
	monDec      *json.Decoder

	qemu   *exec.Cmd
	merger *vmimpl.OutputMerger
	files  map[string]string

	io.Closer
}

func (inst *Instance) Close() error {
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		inst.qemu.Wait()
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
	if inst.mon != nil {
		inst.mon.Close()
	}

	return nil
}

func (inst *Instance) boot() error {
	inst.monport = vmimpl.UnusedTCPPort()
	args, err := inst.buildQemuArgs()
	if err != nil {
		return err
	}
	log.Logf(0, "running command: %v %#v", inst.cfg.Qemu, args)

	inst.args = args
	qemu := osutil.Command(inst.cfg.Qemu, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %w", inst.cfg.Qemu, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.qemu = qemu
	// Qemu has started.

	// Start output merger.
	var tee io.Writer

	tee = os.NewFile(0, fmt.Sprintf("qemu-%v.log", inst.index))

	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("qemu", inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()

	if err := vmimpl.WaitForSSH(10*time.Minute, inst.SSHOptions,
		inst.merger.Err["qemu"], inst.debug); err != nil {
		bootOutputStop <- true
		<-bootOutputStop
		return vmimpl.MakeBootError(err, bootOutput)
	}
	bootOutputStop <- true
	return nil
}

func (inst *Instance) buildQemuArgs() ([]string, error) {
	args := []string{
		"-m", strconv.Itoa(inst.cfg.Mem),
		"-smp", strconv.Itoa(inst.cfg.CPU),
		"-chardev", fmt.Sprintf("socket,id=SOCKSYZ,server=on,wait=off,host=localhost,port=%v", inst.monport),
		"-mon", "chardev=SOCKSYZ,mode=control",
		"-display", "none",
		"-serial", "stdio",
		"-no-reboot",
		"-name", fmt.Sprintf("VM-%v", inst.index),
		"-device", "virtio-rng-pci",
		"-enable-kvm", "-cpu", "host,migratable=off",
		"-device", "e1000,netdev=net0",
		"-netdev", fmt.Sprintf("user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:%v-:22", inst.Port),
		"-drive", "file=" + inst.image + ",format=raw",
		"-snapshot",
		"-kernel", inst.cfg.Kernel,
		"-append", "root=/dev/sda", "console=ttyS0",
	}

	return args, nil
}

func (inst *Instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/qemu: forward port is zero")
	}
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("vm/qemu: forward port already set")
	}
	inst.forwardPort = port

	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *Instance) targetDir() string {
	return "/"
}

func (inst *Instance) Copy(hostSrc string) (string, error) {
	base := filepath.Base(hostSrc)
	vmDst := filepath.Join(inst.targetDir(), base)

	args := append(vmimpl.SCPArgs(inst.debug, inst.Key, inst.Port),
		hostSrc, inst.User+"@localhost:"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	_, err := osutil.RunCmd(10, "", "scp", args...)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *Instance) Run(ctx context.Context, command string) (
	<-chan []byte, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	mergerErrName := "ssh-" + uuid.New().String()
	inst.merger.Add(mergerErrName, rpipe)

	sshArgs := vmimpl.SSHArgsForward(inst.debug, inst.Key, inst.Port, inst.forwardPort)

	args := []string{"ssh"}
	args = append(args, sshArgs...)
	args = append(args, inst.User+"@localhost", "cd "+inst.targetDir()+" && "+command)

	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.workdir
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()
	return vmimpl.Multiplex(ctx, cmd, inst.merger, mergerErrName)
}

func (inst *Instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v\n%v %q\n", inst.version, inst.cfg.Qemu, inst.args)
	return []byte(info), nil
}

// DiagnoseLinux diagnoses some Linux kernel bugs over the provided ssh callback.
func diagnoseLinux(rep *report.Report, ssh func(args ...string) ([]byte, error)) (output []byte, handled bool) {
	if !strings.Contains(rep.Title, "MAX_LOCKDEP") {
		return nil, false
	}
	// Dump /proc/lockdep* files on BUG: MAX_LOCKDEP_{KEYS,ENTRIES,CHAINS,CHAIN_HLOCKS} too low!
	output, err := ssh("cat", "/proc/lockdep_stats", "/proc/lockdep", "/proc/lockdep_chains")
	if err != nil {
		output = append(output, err.Error()...)
	}
	// Remove mangled pointer values, they take lots of space but don't add any value.
	output = regexp.MustCompile(` *\[?[0-9a-f]{8,}\]?\s*`).ReplaceAll(output, nil)
	return output, true
}

func (inst *Instance) Diagnose(rep *report.Report) []byte {
	if inst.target.OS == targets.Linux {
		if output, handled := diagnoseLinux(rep, inst.ssh); handled {
			return output
		}
	}
	// TODO: we don't need registers on all reports. Probably only relevant for "crashes"
	// (NULL derefs, paging faults, etc), but is not useful for WARNING/BUG/HANG (?).
	ret := []byte(fmt.Sprintf("%s Registers:\n", time.Now().Format("15:04:05 ")))
	for cpu := 0; cpu < inst.cfg.CPU; cpu++ {
		regs, err := inst.hmp("info registers", cpu)
		if err == nil {
			ret = append(ret, []byte(fmt.Sprintf("info registers vcpu %v\n", cpu))...)
			ret = append(ret, []byte(regs)...)
		} else {
			log.Logf(0, "VM-%v failed reading regs: %v", inst.index, err)
			ret = append(ret, []byte(fmt.Sprintf("Failed reading regs: %v\n", err))...)
		}
	}
	return ret
}

func (inst *Instance) ssh(args ...string) ([]byte, error) {
	return osutil.RunCmd(time.Minute, "", "ssh", inst.sshArgs(args...)...)
}

func (inst *Instance) sshArgs(args ...string) []string {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.User, inst.Port), inst.User+"@localhost")
	return append(sshArgs, args...)
}
