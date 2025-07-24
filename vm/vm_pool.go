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
	"sync"
	"sync/atomic"
	"time"

	"schedtest/pkg/log"
	"schedtest/pkg/osutil"
	"schedtest/pkg/stat"
	"schedtest/sys/targets"
	"schedtest/vm/qemu"
)

type Pool struct {
	qemuimpl           *qemu.Pool
	workdir            string
	timeouts           targets.Timeouts
	count              int
	activeCount        int32
	statOutputReceived *stat.Val

	BootErrors chan error
	BootTime   stat.AverageValue[time.Duration]

	defaultJob Runner

	// The mutex serializes ReserveForRun() and SetDefault() calls.
	mu        *sync.Mutex
	instances []*Instance
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

func (pool *Pool) Loop(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(pool.instances))
	for _, inst := range pool.instances {
		go func() {
			for ctx.Err() == nil {
				pool.runInstance(ctx, inst)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

// create VM
func (pool *Pool) runInstance(ctx context.Context, inst *Instance) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.Logf(2, "pool: booting instance %d", inst.index)

	inst.reset(cancel)

	start := time.Now()
	inst.status(StateBooting)
	defer inst.status(StateOffline)

	obj, err := pool.Create(inst.index)
	if err != nil {
		pool.BootErrors <- err
		return
	}
	defer obj.Close()

	pool.BootTime.Save(time.Since(start))

	inst.status(StateWaiting)
	// Current assume job is immutable
	job := inst.job

	if job == nil {
		panic("job is nil")
	}

	inst.status(StateRunning)
	job(ctx, obj, inst.updateInfo)
}

func (pool *Pool) Close() error {
	if pool.activeCount != 0 {
		panic("all the instances should be closed before pool.Close()")
	}
	return nil
}
