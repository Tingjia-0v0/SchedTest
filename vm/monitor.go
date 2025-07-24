package vm

import (
	"bytes"
	"schedtest/pkg/report"
	"schedtest/pkg/report/crash"
	"schedtest/vm/vmimpl"
	"time"
)

type monitor struct {
	inst            *Instance
	outc            <-chan []byte
	injected        <-chan bool
	finished        func()
	errc            <-chan error
	reporter        *report.Reporter
	exit            ExitCondition
	output          []byte
	beforeContext   int
	matchPos        int
	lastExecuteTime time.Time
	extractCalled   bool
}

func (mon *monitor) monitorExecution() *report.Report {
	ticker := time.NewTicker(tickerPeriod)
	defer ticker.Stop()
	defer func() {
		if mon.finished != nil {
			mon.finished()
		}
	}()
	for {
		select {
		case err := <-mon.errc:
			switch err {
			case nil:
				// The program has exited without errors,
				// but wait for kernel output in case there is some delayed oops.
				crash := ""
				if mon.exit&ExitNormal == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractError(crash)
			case vmimpl.ErrTimeout:
				if mon.exit&ExitTimeout == 0 {
					return mon.extractError(timeoutCrash)
				}
				return nil
			default:
				// Note: connection lost can race with a kernel oops message.
				// In such case we want to return the kernel oops.
				crash := ""
				if mon.exit&ExitError == 0 {
					crash = lostConnectionCrash
				}
				return mon.extractError(crash)
			}
		case out, ok := <-mon.outc:
			if !ok {
				mon.outc = nil
				continue
			}
			mon.inst.pool.statOutputReceived.Add(len(out))
			if rep, done := mon.appendOutput(out); done {
				return rep
			}
		case <-mon.injected:
			// last time the VM was injected with a program/command
			mon.lastExecuteTime = time.Now()
		case <-ticker.C:
			// Detect both "no output whatsoever" and "kernel episodically prints
			// something to console, but fuzzer is not actually executing programs".
			if time.Since(mon.lastExecuteTime) > mon.inst.pool.timeouts.NoOutput {
				return mon.extractError(noOutputCrash)
			}
		case <-vmimpl.Shutdown:
			return nil
		}
	}
}

func (mon *monitor) appendOutput(out []byte) (*report.Report, bool) {
	lastPos := len(mon.output)
	mon.output = append(mon.output, out...)
	if bytes.Contains(mon.output[lastPos:], executingProgram) {
		mon.lastExecuteTime = time.Now()
	}
	if mon.reporter.ContainsCrash(mon.output[mon.matchPos:]) {
		return mon.extractError("unknown error"), true
	}
	if len(mon.output) > 2*mon.beforeContext {
		copy(mon.output, mon.output[len(mon.output)-mon.beforeContext:])
		mon.output = mon.output[:mon.beforeContext]
	}
	// Find the starting position for crash matching on the next iteration.
	// We step back from the end of output by maxErrorLength to handle the case
	// when a crash line is currently split/incomplete. And then we try to find
	// the preceding '\n' to have a full line. This is required to handle
	// the case when a particular pattern is ignored as crash, but a suffix
	// of the pattern is detected as crash (e.g. "ODEBUG:" is trimmed to "BUG:").
	mon.matchPos = len(mon.output) - maxErrorLength
	for i := 0; i < maxErrorLength; i++ {
		if mon.matchPos <= 0 || mon.output[mon.matchPos-1] == '\n' {
			break
		}
		mon.matchPos--
	}
	mon.matchPos = max(mon.matchPos, 0)
	return nil, false
}

func (mon *monitor) extractError(defaultError string) *report.Report {
	if mon.extractCalled {
		panic("extractError called twice")
	}
	mon.extractCalled = true
	if mon.finished != nil {
		// If the caller wanted an early notification, provide it.
		mon.finished()
		mon.finished = nil
	}
	diagOutput := []byte{}
	if defaultError != "" {
		diagOutput = mon.inst.Diagnose(mon.createReport(defaultError))
	}
	// Give it some time to finish writing the error message.
	// But don't wait for "no output", we already waited enough.
	if defaultError != noOutputCrash {
		mon.waitForOutput()
	}

	if defaultError == "" && mon.reporter.ContainsCrash(mon.output[mon.matchPos:]) {
		// We did not call Diagnose above because we thought there is no error, so call it now.
		diagOutput = mon.inst.Diagnose(mon.createReport(defaultError))
	}

	rep := mon.createReport(defaultError)
	if rep == nil {
		return nil
	}
	if len(diagOutput) > 0 {
		rep.Output = append(rep.Output, vmDiagnosisStart...)
		rep.Output = append(rep.Output, diagOutput...)
	}
	return rep
}

func (mon *monitor) createReport(defaultError string) *report.Report {
	rep := mon.reporter.ParseFrom(mon.output, mon.matchPos)
	if rep == nil {
		if defaultError == "" {
			return nil
		}
		typ := crash.UnknownType
		if defaultError == lostConnectionCrash {
			typ = crash.LostConnection
		}
		return &report.Report{
			Title:      defaultError,
			Output:     mon.output,
			Suppressed: report.IsSuppressed(mon.reporter, mon.output),
			Type:       typ,
		}
	}
	start := max(rep.StartPos-mon.beforeContext, 0)
	end := min(rep.EndPos+afterContext, len(rep.Output))
	rep.Output = rep.Output[start:end]
	rep.StartPos -= start
	rep.EndPos -= start
	return rep
}

func (mon *monitor) waitForOutput() {
	timer := time.NewTimer(vmimpl.WaitForOutputTimeout)
	defer timer.Stop()
	for {
		select {
		case out, ok := <-mon.outc:
			if !ok {
				return
			}
			mon.output = append(mon.output, out...)
		case <-timer.C:
			return
		case <-vmimpl.Shutdown:
			return
		}
	}
}

type ExitCondition int

const (
	// The program is allowed to exit after timeout.
	ExitTimeout = ExitCondition(1 << iota)
	// The program is allowed to exit with no errors.
	ExitNormal
	// The program is allowed to exit with errors.
	ExitError
)

const (
	maxErrorLength = 256

	lostConnectionCrash  = "lost connection to test machine"
	noOutputCrash        = "no output from test machine"
	timeoutCrash         = "timed out"
	executorPreemptedStr = "SYZ-EXECUTOR: PREEMPTED"
	vmDiagnosisStart     = "\nVM DIAGNOSIS:\n"
)

var (
	executingProgram = []byte("executed programs:") // syz-execprog output

	afterContext = 128 << 10

	tickerPeriod = 10 * time.Second
)
