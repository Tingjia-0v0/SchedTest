// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"schedtest/prog"
	"schedtest/sys/targets"
)

func InitTarget(target *prog.Target) {
	arch := &arch{
		MAP_FIXED:           target.GetConst("MAP_FIXED"),
		clockGettimeSyscall: target.SyscallMap["clock_gettime"],
		CLOCK_REALTIME:      target.GetConst("CLOCK_REALTIME"),
	}

	target.MakeDataMmap = MakePosixMmap(target, true, true)
	target.Neutralize = arch.neutralize
	target.SpecialTypes = map[string]func(g *prog.Gen, typ prog.Type, dir prog.Dir, old prog.Arg) (
		prog.Arg, []*prog.Call){
		"timespec": arch.generateTimespec,
		"timeval":  arch.generateTimespec,
	}

	target.AuxResources = map[string]bool{
		"uid":       true,
		"pid":       true,
		"gid":       true,
		"timespec":  true,
		"timeval":   true,
		"time_sec":  true,
		"time_usec": true,
		"time_nsec": true,
	}

	switch target.Arch {
	case targets.AMD64:
		target.SpecialPointers = []uint64{
			0xffffffff81000000, // kernel text
			0xffffffffff600000, // VSYSCALL_ADDR
		}
	default:
		panic("unknown arch")
	}

	target.SpecialFileLenghts = []int{
		int(target.GetConst("PATH_MAX")),
		int(target.GetConst("UNIX_PATH_MAX")),
		int(target.GetConst("NAME_MAX")),
		int(target.GetConst("BTRFS_INO_LOOKUP_PATH_MAX")),
		int(target.GetConst("BTRFS_INO_LOOKUP_USER_PATH_MAX")),
		int(target.GetConst("SMB_PATH_MAX")),
		int(target.GetConst("XT_CGROUP_PATH_MAX")),
		int(target.GetConst("XENSTORE_REL_PATH_MAX")),
		1 << 16, // gVisor's MaxFilenameLen
	}
}

type arch struct {
	MAP_FIXED           uint64
	clockGettimeSyscall *prog.Syscall
	CLOCK_REALTIME      uint64
}

func (arch *arch) neutralize(c *prog.Call, fixStructure bool) error {
	switch c.Meta.CallName {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		c.Args[3].(*prog.ConstArg).Val |= arch.MAP_FIXED
	case "exit", "exit_group":
		code := c.Args[0].(*prog.ConstArg)
		// This code is reserved by executor.
		if code.Val%128 == 67 {
			code.Val = 1
		}
	case "sched_setattr":
		// Enabling a SCHED_FIFO or a SCHED_RR policy may lead to false positive stall-related crashes.
		neutralizeSchedAttr(c.Args[1])
	}

	return nil
}

func neutralizeSchedAttr(a prog.Arg) {
	switch attr := a.(type) {
	case *prog.PointerArg:
		if attr.Res == nil {
			// If it's just a pointer to somewhere, still set it to NULL as there's a risk that
			// it points to the valid memory and it can be interpreted as a sched_attr struct.
			attr.Address = 0
			return
		}
		groupArg, ok := attr.Res.(*prog.GroupArg)
		if !ok || len(groupArg.Inner) == 0 {
			return
		}
		if unionArg, ok := groupArg.Inner[0].(*prog.UnionArg); ok {
			dataArg, ok := unionArg.Option.(*prog.DataArg)
			if !ok {
				return
			}
			if dataArg.Dir() == prog.DirOut {
				return
			}
			// Clear the first 16 bytes to prevent overcoming the limitation by squashing the struct.
			data := append([]byte{}, dataArg.Data()...)
			for i := 0; i < 16 && i < len(data); i++ {
				data[i] = 0
			}
			dataArg.SetData(data)
		}

		// Most likely it's the intended sched_attr structure.
		if len(groupArg.Inner) > 1 {
			policyField, ok := groupArg.Inner[1].(*prog.ConstArg)
			if !ok {
				return
			}
			const SCHED_FIFO = 0x1
			const SCHED_RR = 0x2
			if policyField.Val == SCHED_FIFO || policyField.Val == SCHED_RR {
				policyField.Val = 0
			}
		}
	case *prog.ConstArg:
		attr.Val = 0
	}
}

func (arch *arch) generateTimespec(g *prog.Gen, typ0 prog.Type, dir prog.Dir, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	// We need to generate timespec/timeval that are either
	// (1) definitely in the past, or
	// (2) definitely in unreachable fututre, or
	// (3) few ms ahead of now.
	// Note: timespec/timeval can be absolute or relative to now.
	// Note: executor has blocking syscall timeout of 45 ms,
	// so we generate both 10ms and 60ms.
	// TODO(dvyukov): this is now all outdated with tunable timeouts.
	const (
		timeout1 = uint64(10)
		timeout2 = uint64(60)
	)
	usec := typ.Name() == "timeval"
	switch {
	case g.NOutOf(1, 4):
		// Now for relative, past for absolute.
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 0),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, 0),
		})
	case g.NOutOf(1, 3):
		// Few ms ahead for relative, past for absolute.
		nsec := timeout1 * 1e6
		if g.NOutOf(1, 2) {
			nsec = timeout2 * 1e6
		}
		if usec {
			nsec /= 1e3
		}
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 0),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, nsec),
		})
	case g.NOutOf(1, 2):
		// Unreachable fututre for both relative and absolute.
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{
			prog.MakeResultArg(typ.Fields[0].Type, dir, nil, 2e9),
			prog.MakeResultArg(typ.Fields[1].Type, dir, nil, 0),
		})
	default:
		// Few ms ahead for absolute.
		meta := arch.clockGettimeSyscall
		ptrArgType := meta.Args[1].Type.(*prog.PtrType)
		argType := ptrArgType.Elem.(*prog.StructType)
		tp := prog.MakeGroupArg(argType, prog.DirOut, []prog.Arg{
			prog.MakeResultArg(argType.Fields[0].Type, prog.DirOut, nil, 0),
			prog.MakeResultArg(argType.Fields[1].Type, prog.DirOut, nil, 0),
		})
		var tpaddr prog.Arg
		tpaddr, calls = g.Alloc(ptrArgType, prog.DirIn, tp)
		gettime := prog.MakeCall(meta, []prog.Arg{
			prog.MakeConstArg(meta.Args[0].Type, prog.DirIn, arch.CLOCK_REALTIME),
			tpaddr,
		})
		calls = append(calls, gettime)
		sec := prog.MakeResultArg(typ.Fields[0].Type, dir, tp.Inner[0].(*prog.ResultArg), 0)
		nsec := prog.MakeResultArg(typ.Fields[1].Type, dir, tp.Inner[1].(*prog.ResultArg), 0)
		msec := timeout1
		if g.NOutOf(1, 2) {
			msec = timeout2
		}
		if usec {
			nsec.OpDiv = 1e3
			nsec.OpAdd = msec * 1e3
		} else {
			nsec.OpAdd = msec * 1e6
		}
		arg = prog.MakeGroupArg(typ, dir, []prog.Arg{sec, nsec})
	}
	return
}

// MakePosixMmap creates a "normal" posix mmap call that maps the target data range.
// If exec is set, the mapping is mapped as PROT_EXEC.
// If contain is set, the mapping is surrounded by PROT_NONE pages.
// These flags should be in sync with what executor.
func MakePosixMmap(target *prog.Target, exec, contain bool) func() []*prog.Call {
	meta := target.SyscallMap["mmap"]
	protRW := target.GetConst("PROT_READ") | target.GetConst("PROT_WRITE")
	if exec {
		protRW |= target.GetConst("PROT_EXEC")
	}
	flags := target.GetConst("MAP_ANONYMOUS") | target.GetConst("MAP_PRIVATE") | target.GetConst("MAP_FIXED")
	size := target.NumPages * target.PageSize
	const invalidFD = ^uint64(0)
	makeMmap := func(addr, size, prot uint64) *prog.Call {
		call := prog.MakeCall(meta, []prog.Arg{
			prog.MakeVmaPointerArg(meta.Args[0].Type, prog.DirIn, addr, size),
			prog.MakeConstArg(meta.Args[1].Type, prog.DirIn, size),
			prog.MakeConstArg(meta.Args[2].Type, prog.DirIn, prot),
			prog.MakeConstArg(meta.Args[3].Type, prog.DirIn, flags),
			prog.MakeResultArg(meta.Args[4].Type, prog.DirIn, nil, invalidFD),
		})
		i := len(call.Args)
		// Some targets have a padding argument between fd and offset.
		if len(meta.Args) > 6 {
			call.Args = append(call.Args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
			i++
		}
		call.Args = append(call.Args, prog.MakeConstArg(meta.Args[i].Type, prog.DirIn, 0))
		return call
	}
	return func() []*prog.Call {
		if contain {
			return []*prog.Call{
				makeMmap(^target.PageSize+1, target.PageSize, 0),
				makeMmap(0, size, protRW),
				makeMmap(size, target.PageSize, 0),
			}
		}
		return []*prog.Call{makeMmap(0, size, protRW)}
	}
}
