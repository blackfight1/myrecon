package port

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// NaabuPlugin performs port discovery.
type NaabuPlugin struct{}

// NaabuResult represents one JSONL line from naabu output.
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// NewNaabuPlugin creates a Naabu plugin instance.
func NewNaabuPlugin() *NaabuPlugin {
	return &NaabuPlugin{}
}

// Name returns plugin name.
func (n *NaabuPlugin) Name() string {
	return "Naabu"
}

// Execute runs naabu and excludes 80/443 since httpx already covers web services.
func (n *NaabuPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("naabu"); err != nil {
		return nil, fmt.Errorf("naabu not found in PATH. Please install naabu and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Naabu] Scanning %d targets (top-ports 1000, excluding 80/443)...\n", len(input))

	tmpFile, err := os.CreateTemp("", "naabu_input_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, target := range input {
		if _, err := tmpFile.WriteString(target + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %v", err)
		}
	}
	_ = tmpFile.Close()

	cmd := exec.Command("naabu",
		"-list", tmpFile.Name(),
		"-top-ports", "1000",
		"-exclude-ports", "80,443",
		"-json",
		"-silent",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start naabu: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	seen := make(map[string]bool)
	portCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var naabuResult NaabuResult
		if err := json.Unmarshal([]byte(line), &naabuResult); err != nil {
			continue
		}
		if naabuResult.IP == "" || naabuResult.Port <= 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", naabuResult.IP, naabuResult.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		portCount++

		results = append(results, engine.Result{
			Type: "open_port",
			Data: map[string]interface{}{
				"host": naabuResult.Host,
				"ip":   naabuResult.IP,
				"port": naabuResult.Port,
			},
		})
	}

	if err := cmd.Wait(); err != nil {
		// Keep behavior tolerant: naabu may return non-zero when some hosts are unreachable.
		fmt.Printf("[Naabu] Command finished with warning\n")
	}

	fmt.Printf("[Naabu] Port scan completed, found %d open ports\n", portCount)
	return results, nil
}
