package qemu

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"schedtest/pkg/config"
	"schedtest/pkg/osutil"
	"schedtest/sys/targets"
	"schedtest/vm/vmimpl"
	"strings"
	"time"
)

type Config struct {
	// QEMU binary name (optional).
	// If not specified, qemu-system-arch is used by default.
	Qemu string `json:"qemu"`

	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`
	// Location of the kernel for injected boot (e.g. arch/x86/boot/bzImage, optional).
	// This is passed to QEMU as the -kernel option.
	Kernel string `json:"kernel"`
	// Number of VM CPUs (1 by default).
	CPU int `json:"cpu"`
	// Amount of VM memory in MiB (1024 by default).
	Mem int `json:"mem"`
}

type Pool struct {
	env     *vmimpl.Env
	cfg     *Config
	target  *targets.Target
	version string
}

func Ctor(env *vmimpl.Env) (*Pool, error) {
	cfg := &Config{
		Count: 1,
		CPU:   1,
		Mem:   1024,
		Qemu:  "qemu-system-x86_64",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse qemu vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 1024 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1024]", cfg.Count)
	}
	if _, err := exec.LookPath(cfg.Qemu); err != nil {
		return nil, err
	}

	if !osutil.IsExist(env.Image) {
		return nil, fmt.Errorf("image file '%v' does not exist", env.Image)
	}

	if cfg.CPU <= 0 || cfg.CPU > 1024 {
		return nil, fmt.Errorf("bad qemu cpu: %v, want [1-1024]", cfg.CPU)
	}
	if cfg.Mem < 128 || cfg.Mem > 1048576 {
		return nil, fmt.Errorf("bad qemu mem: %v, want [128-1048576]", cfg.Mem)
	}
	cfg.Kernel = osutil.Abs(cfg.Kernel)

	output, err := osutil.RunCmd(time.Minute, "", cfg.Qemu, "--version")
	if err != nil {
		return nil, err
	}
	version := string(bytes.Split(output, []byte{'\n'})[0])

	pool := &Pool{
		env:     env,
		cfg:     cfg,
		version: version,
		target:  targets.Get(env.OS, env.Arch),
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (*Instance, error) {
	sshkey := pool.env.SSHKey
	sshuser := pool.env.SSHUser

	for i := 0; ; i++ {
		inst, err := pool.ctor(workdir, sshkey, sshuser, index)
		if err == nil {
			return inst, nil
		}
		// Older qemu prints "could", newer -- "Could".
		if i < 1000 && strings.Contains(err.Error(), "ould not set up host forwarding rule") {
			continue
		}
		if i < 1000 && strings.Contains(err.Error(), "Device or resource busy") {
			continue
		}
		if i < 1000 && strings.Contains(err.Error(), "Address already in use") {
			continue
		}
		return nil, err
	}
}

func (pool *Pool) ctor(workdir, sshkey, sshuser string, index int) (*Instance, error) {
	inst := &Instance{
		index:    index,
		cfg:      pool.cfg,
		target:   pool.target,
		version:  pool.version,
		image:    pool.env.Image,
		os:       pool.env.OS,
		timeouts: pool.env.Timeouts,
		workdir:  workdir,
		debug:    true,
		SSHOptions: vmimpl.SSHOptions{
			Addr: "localhost",
			Port: vmimpl.UnusedTCPPort(),
			Key:  sshkey,
			User: sshuser,
		},
	}

	if st, err := os.Stat(inst.image); err == nil && st.Size() == 0 {
		panic("image is empty")
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}
