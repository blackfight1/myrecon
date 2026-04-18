package subdomain

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"hunter/internal/engine"
)

// BBOTPlugin implements subdomain collection via BBOT.
type BBOTPlugin struct {
	passiveOnly bool
}

// NewBBOTPlugin creates a BBOT plugin instance.
func NewBBOTPlugin(passiveOnly bool) *BBOTPlugin {
	return &BBOTPlugin{passiveOnly: passiveOnly}
}

// Name returns plugin name.
func (b *BBOTPlugin) Name() string {
	return "BBOT"
}

// Execute runs BBOT subdomain enumeration for all input root domains.
func (b *BBOTPlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("bbot"); err != nil {
		return nil, fmt.Errorf("bbot not found in PATH. Please install bbot and ensure it's in your PATH")
	}

	targets := normalizeDomains(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[BBOT] Running subdomain enumeration for %d root domains...\n", len(targets))

	scanDir, err := os.MkdirTemp("", "hunter_bbot_scan_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create bbot temp output dir: %v", err)
	}
	defer os.RemoveAll(scanDir)

	outputFile := filepath.Join(scanDir, "subdomains.txt")
	scanName := fmt.Sprintf("hunter_subs_%d", time.Now().UnixNano())

	args := []string{"-t"}
	args = append(args, targets...)
	args = append(args,
		"-p", "subdomain-enum",
		"-om", "subdomains",
		"-n", scanName,
		"-o", scanDir,
		"-c", fmt.Sprintf("modules.subdomains.output_file=%s", outputFile),
	)
	if b.passiveOnly {
		args = append(args, "-rf", "passive", "-ef", "aggressive")
	}

	timeout := b.resolveTimeout()
	runCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.Command("bbot", args...)
	output, runErr := runCommandWithContext(runCtx, cmd)

	subdomains, parseErr := readSubdomainsFile(outputFile)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("bbot execution failed: %v", runErr)
		}
		return nil, fmt.Errorf("failed to parse bbot subdomains output: %v", parseErr)
	}

	// Timeout is treated as non-fatal to prevent one long-running source from
	// blocking the whole scan pipeline forever.
	if errors.Is(runErr, context.DeadlineExceeded) {
		fmt.Printf("[BBOT] Timeout after %s, continue with partial results=%d\n", timeout, len(subdomains))
		runErr = nil
	}
	// User/system cancellation should still propagate to terminate the job.
	if errors.Is(runErr, context.Canceled) && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if runErr != nil {
		if len(subdomains) == 0 {
			msg := strings.TrimSpace(tailText(output, 1200))
			if msg == "" {
				return nil, fmt.Errorf("bbot execution failed: %v", runErr)
			}
			return nil, fmt.Errorf("bbot execution failed: %v | output: %s", runErr, msg)
		}
		fmt.Printf("[BBOT] Command finished with warning: %v\n", runErr)
	}

	results := make([]engine.Result, 0, len(subdomains))
	for _, subdomain := range subdomains {
		results = append(results, engine.Result{
			Type: "domain",
			Data: subdomain,
		})
	}

	fmt.Printf("[BBOT] Found %d subdomains\n", len(results))
	return results, nil
}

func (b *BBOTPlugin) resolveTimeout() time.Duration {
	// Keep passive reasonably short; active can run longer.
	defaultMin := 25
	envKey := "BBOT_PASSIVE_TIMEOUT_MIN"
	if !b.passiveOnly {
		defaultMin = 60
		envKey = "BBOT_ACTIVE_TIMEOUT_MIN"
	}
	if raw := strings.TrimSpace(os.Getenv(envKey)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return time.Duration(v) * time.Minute
		}
	}
	if raw := strings.TrimSpace(os.Getenv("BBOT_TIMEOUT_MIN")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return time.Duration(v) * time.Minute
		}
	}
	return time.Duration(defaultMin) * time.Minute
}

func runCommandWithContext(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	prepareProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return out.Bytes(), err
	case <-ctx.Done():
		_ = killProcessGroup(cmd)
		select {
		case <-waitCh:
		case <-time.After(4 * time.Second):
			_ = killProcessGroup(cmd)
		}
		return out.Bytes(), ctx.Err()
	}
}

func tailText(b []byte, max int) string {
	if max <= 0 {
		max = 1024
	}
	if len(b) <= max {
		return string(b)
	}
	return string(b[len(b)-max:])
}

func normalizeDomains(input []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(input))

	for _, item := range input {
		d := strings.ToLower(strings.TrimSpace(item))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}

	return out
}

func readSubdomainsFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	out := make([]string, 0, 256)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		line = strings.TrimSuffix(line, ".")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t/\\") || !strings.Contains(line, ".") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return out, nil
}
