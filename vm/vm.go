package vm

import (
	"schedtest/pkg/log"
	"schedtest/pkg/mgrconfig"
	"schedtest/pkg/stat"
	"schedtest/vm/qemu"
	"schedtest/vm/vmimpl"
	"sync"
)

// Create creates a VM pool that can be used to create individual VMs.
func Create(cfg *mgrconfig.Config, debug bool, def Runner) (*Pool, error) {
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

	pool := &Pool{
		qemuimpl: impl,
		workdir:  env.Workdir,
		timeouts: cfg.Timeouts,
		count:    count,
		statOutputReceived: stat.New("vm output", "Bytes of VM console output received",
			stat.Graph("traffic"), stat.Rate{}, stat.FormatMB),

		BootErrors: make(chan error, 16),
		defaultJob: def,
		mu:         new(sync.Mutex),
		instances:  make([]*Instance, count),
	}

	for i := 0; i < count; i++ {
		inst := &Instance{
			pool:  pool,
			index: i,
		}
		inst.reset(func() {})
		pool.instances[i] = inst
	}

	return pool, nil
}
