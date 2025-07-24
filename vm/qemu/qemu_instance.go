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
	"strconv"
	"time"

	"schedtest/pkg/log"
	"schedtest/pkg/osutil"
	"schedtest/sys/targets"
	"schedtest/vm/vmimpl"

	"github.com/google/uuid"
)

type instance struct {
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
}

func (inst *instance) Close() error {
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

func (inst *instance) boot() error {
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

func (inst *instance) buildQemuArgs() ([]string, error) {
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

func (inst *instance) Forward(port int) (string, error) {
	if port == 0 {
		return "", fmt.Errorf("vm/qemu: forward port is zero")
	}
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("vm/qemu: forward port already set")
	}
	inst.forwardPort = port

	return fmt.Sprintf("localhost:%v", port), nil
}

func (inst *instance) targetDir() string {
	return "/"
}

func (inst *instance) Copy(hostSrc string) (string, error) {
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

func (inst *instance) Run(ctx context.Context, command string) (
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

func (inst *instance) Info() ([]byte, error) {
	info := fmt.Sprintf("%v\n%v %q\n", inst.version, inst.cfg.Qemu, inst.args)
	return []byte(info), nil
}

// nolint: lll
const initScript = `#! /bin/bash
set -eux
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs nodev /sys/kernel/debug/
mount -t tmpfs none /tmp
mount -t tmpfs none /var
mount -t tmpfs none /run
mount -t tmpfs none /etc
mount -t tmpfs none /root
touch /etc/fstab
mkdir /etc/network
mkdir /run/network
printf 'auto lo\niface lo inet loopback\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet static\naddress 10.0.2.15\nnetmask 255.255.255.0\nnetwork 10.0.2.0\ngateway 10.0.2.1\nbroadcast 10.0.2.255\n\n' >> /etc/network/interfaces
printf 'auto eth0\niface eth0 inet6 static\naddress fe80::5054:ff:fe12:3456/64\ngateway 2000:da8:203:612:0:3:0:1\n\n' >> /etc/network/interfaces
mkdir -p /etc/network/if-pre-up.d
mkdir -p /etc/network/if-up.d
ifup lo
ifup eth0 || true
echo "root::0:0:root:/root:/bin/bash" > /etc/passwd
mkdir -p /etc/ssh
cp {{KEY}}.pub /root/
chmod 0700 /root
chmod 0600 /root/key.pub
mkdir -p /var/run/sshd/
chmod 700 /var/run/sshd
groupadd -g 33 sshd
useradd -u 33 -g 33 -c sshd -d / sshd
cat > /etc/ssh/sshd_config <<EOF
          Port 22
          Protocol 2
          UsePrivilegeSeparation no
          HostKey {{KEY}}
          PermitRootLogin yes
          AuthenticationMethods publickey
          ChallengeResponseAuthentication no
          AuthorizedKeysFile /root/key.pub
          IgnoreUserKnownHosts yes
          AllowUsers root
          LogLevel INFO
          TCPKeepAlive yes
          RSAAuthentication yes
          PubkeyAuthentication yes
EOF
/usr/sbin/sshd -e -D
/sbin/halt -f
`
