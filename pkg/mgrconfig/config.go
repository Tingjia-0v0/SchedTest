// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"encoding/json"
)

type Config struct {
	// Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process).
	RawTarget string `json:"target"`

	// Location of a working directory for the syz-manager process. Outputs here include:
	// - <workdir>/crashes/*: crash output files
	// - <workdir>/instance-x: per VM instance temporary files
	Workdir string `json:"workdir"`
	// Directory with kernel object files (e.g. `vmlinux` for linux)
	// (used for report symbolization, coverage reports and in tree modules finding, optional).
	KernelObj string `json:"kernel_obj"`
	// Location of the disk image file.
	Image string `json:"image,omitempty"`

	// Location of the syzkaller checkout, syz-manager will look
	// for binaries in bin subdir (does not have to be syzkaller checkout as
	// long as it preserves `bin` dir structure)
	SchedTest string `json:"schedtest"`

	// Number of parallel test processes inside of each VM.
	// Allowed values are 1-32, recommended range is ~4-8, default value is 6.
	// It should be chosen to saturate CPU inside of the VM and maximize number of test executions,
	// but to not oversubscribe CPU and memory too severe to not cause OOMs and false hangs/stalls.
	Procs int `json:"procs"`

	// Maximum number of logs to store per crash (default: 100).
	MaxCrashLogs int `json:"max_crash_logs"`

	// Type of virtual machine to use, e.g. "qemu", "gce", "android", "isolated", etc.
	Type string `json:"type"`
	// VM-type-specific parameters.
	// Parameters for concrete types are in Config type in vm/TYPE/TYPE.go, e.g. vm/qemu/qemu.go.
	VM json.RawMessage `json:"vm"`

	SSHKey  string `json:"ssh_key,omitempty"`
	SSHUser string `json:"ssh_user,omitempty"`
	// TCP address to serve RPC for fuzzer processes (optional).
	RPC string `json:"rpc,omitempty"`

	// Implementation details beyond this point. Filled after parsing.
	Derived `json:"-"`
}
