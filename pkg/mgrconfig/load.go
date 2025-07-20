// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"fmt"
	"path/filepath"
	"strings"

	"schedtest/pkg/config"
	"schedtest/pkg/osutil"
	"schedtest/prog"
	_ "schedtest/sys" // most mgrconfig users want targets too
	"schedtest/sys/targets"
)

// Derived config values that are handy to keep with the config, filled after reading user config.
type Derived struct {
	Target    *prog.Target
	SysTarget *targets.Target

	// Parsed Target:
	TargetOS     string
	TargetArch   string
	TargetVMArch string

	// Full paths to binaries we are going to use:
	ExecprogBin string
	ExecutorBin string

	Syscalls []int
	Timeouts targets.Timeouts

	// Special debugging/development mode specified by VM type "none".
	// In this mode syz-manager does not start any VMs, but instead a user is supposed
	// to start syz-executor process in a VM manually.
	VMLess bool
}

func LoadData(data []byte) (*Config, error) {
	cfg, err := LoadPartialData(data)
	if err != nil {
		return nil, err
	}
	if err := Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadFile(filename string) (*Config, error) {
	cfg, err := LoadPartialFile(filename)
	if err != nil {
		return nil, err
	}
	if err := Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadPartialData(data []byte) (*Config, error) {
	cfg := defaultValues()
	if err := config.LoadData(data, cfg); err != nil {
		return nil, err
	}
	if err := SetTargets(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadPartialFile(filename string) (*Config, error) {
	cfg := defaultValues()
	if err := config.LoadFile(filename, cfg); err != nil {
		return nil, err
	}
	if err := SetTargets(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultValues() *Config {
	return &Config{
		SSHUser:      "root",
		RPC:          ":0",
		MaxCrashLogs: 100,
		Procs:        6,
	}
}

type DescriptionsMode int

const (
	invalidDescriptions = iota
	ManualDescriptions
	AutoDescriptions
	AnyDescriptions
)

const manualDescriptions = "manual"

var (
	strToDescriptionsMode = map[string]DescriptionsMode{
		manualDescriptions: ManualDescriptions,
		"auto":             AutoDescriptions,
		"any":              AnyDescriptions,
	}
)

func SetTargets(cfg *Config) error {
	var err error
	cfg.TargetOS, cfg.TargetVMArch, cfg.TargetArch, err = splitTarget(cfg.RawTarget)
	if err != nil {
		return err
	}
	cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return err
	}
	cfg.SysTarget = targets.Get(cfg.TargetOS, cfg.TargetVMArch)
	if cfg.SysTarget == nil {
		return fmt.Errorf("unsupported OS/arch: %v/%v", cfg.TargetOS, cfg.TargetVMArch)
	}
	return nil
}

func Complete(cfg *Config) error {
	if err := checkNonEmpty(
		cfg.TargetOS, "target",
		cfg.TargetVMArch, "target",
		cfg.TargetArch, "target",
		cfg.Workdir, "workdir",
		cfg.SchedTest, "schedtest",
		cfg.Type, "type",
		cfg.SSHUser, "ssh_user",
	); err != nil {
		return err
	}
	cfg.Workdir = osutil.Abs(cfg.Workdir)

	if cfg.Image != "" {
		if !osutil.IsExist(cfg.Image) {
			return fmt.Errorf("bad config param image: can't find %v", cfg.Image)
		}
		cfg.Image = osutil.Abs(cfg.Image)
	}
	if err := cfg.completeBinaries(); err != nil {
		return err
	}
	if cfg.Procs < 1 || cfg.Procs > prog.MaxPids {
		return fmt.Errorf("bad config param procs: '%v', want [1, %v]", cfg.Procs, prog.MaxPids)
	}

	cfg.CompleteKernelDirs()

	cfg.Syscalls, _ = ParseEnabledSyscalls(cfg.Target)

	cfg.initTimeouts()
	cfg.VMLess = cfg.Type == "none"
	return nil
}

func (cfg *Config) initTimeouts() {
	cfg.Timeouts = cfg.SysTarget.Timeouts()
}

func checkNonEmpty(fields ...string) error {
	for i := 0; i < len(fields); i += 2 {
		if fields[i] == "" {
			return fmt.Errorf("config param %v is empty", fields[i+1])
		}
	}
	return nil
}

func (cfg *Config) CompleteKernelDirs() {
	cfg.KernelObj = osutil.Abs(cfg.KernelObj)
}

type KernelDirs struct {
	Src      string
	Obj      string
	BuildSrc string
}

func (cfg *Config) KernelDirs() *KernelDirs {
	return &KernelDirs{
		Src:      cfg.KernelObj,
		Obj:      cfg.KernelObj,
		BuildSrc: cfg.KernelObj,
	}
}

func (cfg *Config) completeBinaries() error {
	cfg.SchedTest = osutil.Abs(cfg.SchedTest)

	targetBin := func(name string) string {
		return filepath.Join(cfg.SchedTest, "bin", name)
	}
	cfg.ExecutorBin = targetBin("syz-executor")

	return nil
}

func splitTarget(target string) (string, string, string, error) {
	if target == "" {
		return "", "", "", fmt.Errorf("target is empty")
	}
	targetParts := strings.Split(target, "/")
	if len(targetParts) != 2 && len(targetParts) != 3 {
		return "", "", "", fmt.Errorf("bad config param target")
	}
	os := targetParts[0]
	vmarch := targetParts[1]
	arch := targetParts[1]
	if len(targetParts) == 3 {
		arch = targetParts[2]
	}
	return os, vmarch, arch, nil
}

func ParseEnabledSyscalls(target *prog.Target) ([]int, error) {

	syscalls := make(map[int]bool)

	for _, call := range target.Syscalls {
		syscalls[call.ID] = true
	}

	if len(syscalls) == 0 {
		return nil, fmt.Errorf("all syscalls are disabled by disable_syscalls in config")
	}
	var arr []int
	for id := range syscalls {
		arr = append(arr, id)
	}
	return arr, nil
}
