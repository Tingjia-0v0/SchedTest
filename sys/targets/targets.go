// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Target struct {
	osCommon
	OS               string
	Arch             string
	VMArch           string // e.g. amd64 for 386, or arm64 for arm
	PtrSize          uint64
	PageSize         uint64
	NumPages         uint64
	DataOffset       uint64
	CFlags           []string
	CxxFlags         []string
	CCompiler        string
	CxxCompiler      string
	Objdump          string // name of objdump executable
	KernelCompiler   string // override CC when running kernel make
	KernelLinker     string // override LD when running kernel make
	KernelArch       string
	KernelHeaderArch string
	// NeedSyscallDefine is used by csource package to decide when to emit __NR_* defines.
	NeedSyscallDefine func(nr uint64) bool
	HostEndian        binary.ByteOrder
	Addr2Line         func() (string, error)
	KernelAddresses   KernelAddresses

	init     *sync.Once
	timeouts Timeouts
}

// KernelAddresses contain approximate rounded up kernel text/data ranges
// that are used to filter signal and comparisons for bogus/unuseful entries.
// Zero values mean no filtering.
type KernelAddresses struct {
	TextStart uint64
	TextEnd   uint64
	DataStart uint64
	DataEnd   uint64
}

func (target *Target) HasCallNumber(callName string) bool {
	return !strings.HasPrefix(callName, "syz_")
}

type osCommon struct {
	// What OS can build native binaries for this OS.
	// If not set, defaults to itself (i.e. native build).
	// Later we can extend this to be a list, but so far we don't have more than one OS.
	BuildOS string

	// E.g. "__NR_" or "SYS_".
	SyscallPrefix string
	// ipc<->executor communication tuning.
	// If ExecutorUsesForkServer, executor uses extended protocol with handshake.
	ExecutorUsesForkServer bool
	// Name of the kernel object file.
	KernelObject string
	// Name of cpp(1) executable.
	CPP string
	// Syscalls on which pseudo syscalls depend. Syzkaller will make sure that __NR* or SYS* definitions
	// for those syscalls are enabled.
	PseudoSyscallDeps map[string][]string
}

// Timeouts structure parametrizes timeouts throughout the system.
// It allows to support different operating system, architectures and execution environments
// (emulation, models, etc) without scattering and duplicating knowledge about their execution
// performance everywhere.
// Timeouts calculation consists of 2 parts: base values and scaling.
// Base timeout values consist of a single syscall timeout, program timeout and "no output" timeout
// and are specified by the target (OS/arch), or defaults are used.
// Scaling part is calculated from the execution environment in pkg/mgrconfig based on VM type,
// kernel build type, emulation, etc. Scaling is specifically converged to a single number so that
// it can be specified/overridden for command line tools (e.g. syz-execprog -slowdown=10).
type Timeouts struct {
	// Timeout for a single syscall, after this time the syscall is considered "blocked".
	Syscall time.Duration
	// Timeout for a single program execution.
	Program time.Duration
	// Timeout for "no output" detection.
	NoOutput time.Duration
	// Limit on a single VM running time, after this time a VM is restarted.
	VMRunningTime time.Duration
	// How long we should test to get "no output" error (derivative of NoOutput, here to avoid duplication).
	NoOutputRunningTime time.Duration
}

const (
	Linux = "linux"
	AMD64 = "amd64"
)

func Get(OS, arch string) *Target {
	return GetEx(OS, arch)
}

func GetEx(OS, arch string) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	target.init.Do(target.lazyInit)
	return target
}

// nolint: lll
var List = map[string]map[string]*Target{
	Linux: {
		AMD64: {
			OS:         "Linux",
			Arch:       AMD64,
			VMArch:     AMD64,
			PtrSize:    8,
			PageSize:   4 << 10,
			NumPages:   16 << 20 / 4 << 10,
			DataOffset: 0x200000000000,
			CFlags: []string{
				"-m64",
				"-ferror-limit=0",
				"-static-pie",
				"-O2",
				"-pthread",
				"-Wall",
				"-Werror",
				"-Wparentheses",
				"-Wunused-const-variable",
				"-Wframe-larger-than=16384", // executor uses stacks of limited size, so no jumbo frames
				"-Wno-stringop-overflow",
				"-Wno-array-bounds",
				"-Wno-format-overflow",
				"-Wno-unused-but-set-variable",
				"-Wno-unused-command-line-argument",
			},
			CCompiler:      "clang",
			CxxCompiler:    "clang++",
			Objdump:        "objdump",
			KernelCompiler: "clang",
			KernelLinker:   "ld.lld",

			KernelArch:       "x86_64",
			KernelHeaderArch: "x86",
			NeedSyscallDefine: func(nr uint64) bool {
				// Only generate defines for new syscalls
				// (added after commit 8a1ab3155c2ac on 2012-10-04).
				return nr >= 313
			},
			HostEndian: binary.LittleEndian,
			Addr2Line: func() (string, error) {
				return "llvm-addr2line", nil
			},
			KernelAddresses: KernelAddresses{
				// Text/modules range for x86_64.
				TextStart: 0xffffffff80000000,
				TextEnd:   0xffffffffff000000,
				// This range corresponds to the first 1TB of the physical memory mapping,
				// see Documentation/arch/x86/x86_64/mm.rst.
				DataStart: 0xffff880000000000,
				DataEnd:   0xffff890000000000,
			},
			init: new(sync.Once),
			timeouts: Timeouts{
				Syscall:             50 * time.Millisecond,
				Program:             5 * time.Second,
				NoOutput:            5 * time.Minute,
				VMRunningTime:       1 * time.Hour,
				NoOutputRunningTime: 5*time.Minute + time.Minute,
			},

			osCommon: osCommon{
				BuildOS:                "Linux",
				SyscallPrefix:          "__NR_",
				ExecutorUsesForkServer: true,
				KernelObject:           "vmlinux",
				CPP:                    "cpp",
				PseudoSyscallDeps: map[string][]string{
					"syz_clone3":     {"clone3", "exit"},
					"syz_clone":      {"clone", "exit"},
					"syz_pidfd_open": {"pidfd_open"},
				},
			},
		},
	},
}

func (target *Target) Timeouts() Timeouts {
	return target.timeouts
}

var (
	// These are used only when building executor.
	// For C repros and syz-extract, we build C source files.
	commonCxxFlags = []string{
		"-std=c++17",
		"-I.",
		"-Iexecutor/_include",
	}
)

func (target *Target) lazyInit() {
	for _, comp := range []string{target.CCompiler, target.CxxCompiler} {
		if _, err := exec.LookPath(comp); err != nil {
			panic(fmt.Sprintf("%v is missing (%v)", comp, err))
		}
	}

	target.CxxFlags = append(target.CFlags, commonCxxFlags...)

	for _, cxx := range []bool{false, true} {
		lang, prog, comp, flags := "c", simpleCProg, target.CCompiler, target.CFlags
		if cxx {
			lang, prog, comp, flags = "c++", simpleCxxProg, target.CxxCompiler, target.CxxFlags
		}
		args := []string{"-x", lang, "-", "-o", "/dev/null"}
		args = append(args, flags...)
		cmd := exec.Command(comp, args...)
		cmd.Stdin = strings.NewReader(prog)
		if out, err := cmd.CombinedOutput(); err != nil {
			panic(fmt.Sprintf("error running command: '%s':\ngotoutput: %s",
				comp+" "+strings.Join(args, " "), out))
		}
	}
}

const (
	simpleCProg = `
#include <stdio.h>
#include <dirent.h> // ensures that system headers are installed
int main() { printf("Hello, World!\n"); }
`
	simpleCxxProg = `
#include <algorithm> // ensures that C++ headers are installed
#include <vector>
int main() { std::vector<int> v(10); }
`
)
