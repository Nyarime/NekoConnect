package main

// Process management: foreground / start / stop / restart / status
// PID file based, no external dependencies

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var pidFile = "/var/run/nekoconnect.pid"

func initPidFile() {
	// Allow override via -pidfile flag or env
	if p := os.Getenv("NEKO_PIDFILE"); p != "" {
		pidFile = p
	}
}

func writePid() {
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePid() {
	os.Remove(pidFile)
}

func readPid() int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

func isRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func cmdStart() {
	pid := readPid()
	if isRunning(pid) {
		fmt.Printf("NekoConnect is already running (pid %d)\n", pid)
		os.Exit(1)
	}

	// Re-exec ourselves without "start" arg, daemonized
	self, _ := filepath.Abs(os.Args[0])
	args := []string{}
	for _, a := range os.Args[1:] {
		if a != "start" {
			args = append(args, a)
		}
	}

	cmd := exec.Command(self, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("NekoConnect started (pid %d)\n", cmd.Process.Pid)
	os.Exit(0)
}

func cmdStop() {
	pid := readPid()
	if !isRunning(pid) {
		fmt.Println("NekoConnect is not running")
		os.Exit(1)
	}

	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Printf("Failed to stop: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("NekoConnect stopped (pid %d)\n", pid)
	removePid()
}

func cmdRestart() {
	pid := readPid()
	if isRunning(pid) {
		proc, _ := os.FindProcess(pid)
		proc.Signal(syscall.SIGTERM)
		fmt.Printf("Stopping pid %d...\n", pid)
		// Wait a bit
		proc.Wait()
	}
	removePid()
	cmdStart()
}

func cmdStatus() {
	pid := readPid()
	if isRunning(pid) {
		fmt.Printf("NekoConnect is running (pid %d)\n", pid)
	} else {
		fmt.Println("NekoConnect is not running")
		if pid > 0 {
			removePid()
		}
	}
}

// handleSubcommand checks if first arg is a management command
// Returns true if handled (caller should exit), false to continue normal startup
func handleSubcommand() bool {
	if len(os.Args) < 2 {
		return false
	}

	switch os.Args[1] {
	case "start":
		cmdStart()
		return true
	case "stop":
		cmdStop()
		return true
	case "restart":
		cmdRestart()
		return true
	case "status":
		cmdStatus()
		return true
	case "version", "-v", "--version":
		fmt.Printf("NekoConnect %s (%s) built %s\n", appVersion, appCommit, appBuildDate)
		return true
	}
	return false
}
