package pcap

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	ps "github.com/mitchellh/go-ps"
)

var tcpdumpLogger = log.New(os.Stderr, "[tcpdump] - ", log.LstdFlags)

func (t *Tcpdump) IsActive() bool {
	return t.isActive.Load()
}

func (t *Tcpdump) buildArgs(ctx context.Context) []string {
	cfg := t.config

	args := []string{"-n", "-Z", "root", "-i", cfg.Iface, "-s", fmt.Sprintf("%d", cfg.Snaplen)}

	if cfg.Output != "stdout" {
		directory := filepath.Dir(cfg.Output)
		template := filepath.Base(cfg.Output)
		fileNameTemplate := fmt.Sprintf("%s/%s.%s", directory, template, cfg.Extension)
		args = append(args, "-w", fileNameTemplate)
	}

	if cfg.Interval > 0 {
		args = append(args, "-G", fmt.Sprintf("%d", cfg.Interval))
	}

	if cfg.Filter != "" {
		args = append(args, cfg.Filter)
	}

	return args
}

func (t *Tcpdump) kill(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGTERM)
}

func (t *Tcpdump) findAndKill(pid int) (int, int, error) {
	processes, err := ps.Processes()
	if err != nil {
		return 0, 0, err
	}

	killCounter := 0
	procsCounter := 0
	for _, p := range processes {
		procId := p.Pid()
		execName := p.Executable()
		if execName == "tcpdump" && procId == pid {
			tcpdumpLogger.Printf("killing %s(%d)\n", execName, procId)
			if err := t.kill(procId); err == nil {
				killCounter++
			}
			procsCounter++
		}
	}
	return killCounter, procsCounter, nil
}

func (t *Tcpdump) Start(ctx context.Context, _ []PcapWriter) error {
	// atomically activate the packet capture
	if !t.isActive.CompareAndSwap(false, true) {
		return fmt.Errorf("already started")
	}

	args := t.buildArgs(ctx)

	cmd := exec.CommandContext(ctx, t.tcpdump, args...)

	// prevent child process from hijacking signals
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, Pgid: 0,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdLine := strings.Join(cmd.Args[:], " ")
	if err := cmd.Start(); err != nil {
		tcpdumpLogger.Printf("'%+v' - error: %+v\n", cmdLine, err)
		return err
	}

	pid := cmd.Process.Pid
	tcpdumpLogger.Printf("EXEC(%d): %v\n", pid, cmdLine)

	<-ctx.Done()

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		tcpdumpLogger.Printf("[pid:%d] - %+v' - error: %+v\n", pid, cmdLine, err)
		_ = cmd.Process.Kill()
	} else {
		defer time.AfterFunc(1*time.Second, func() {
			_ = cmd.Process.Kill()
		}).Stop()
	}

	// make sure previous execution does not survive
	killedProcs, numProcs, killErr := t.findAndKill(pid)
	tcpdumpLogger.Printf("STOP [tcpdump(%d)] <%d/%d>: %+v\n", pid, killedProcs, numProcs, cmdLine)

	t.isActive.Store(false)

	return errors.Join(ctx.Err(), killErr)
}

func NewTcpdump(config *PcapConfig) (PcapEngine, error) {
	tcpdumpBin, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("tcpdump is unavailable")
	}

	var isActive atomic.Bool
	isActive.Store(false)

	tcpdump := Tcpdump{config: config, tcpdump: tcpdumpBin, isActive: &isActive}
	return &tcpdump, nil
}
