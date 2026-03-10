package port

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"hunter/internal/engine"
)

// NmapPlugin performs service fingerprinting on open ports discovered by naabu.
type NmapPlugin struct{}

// NewNmapPlugin creates an Nmap plugin instance.
func NewNmapPlugin() *NmapPlugin {
	return &NmapPlugin{}
}

// Name returns plugin name.
func (n *NmapPlugin) Name() string {
	return "Nmap"
}

// Execute runs nmap service detection.
// Expected input format: "ip:port:host" or "ip:port".
func (n *NmapPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not found in PATH. Please install nmap and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	ipPorts := make(map[string][]int)
	ipHosts := make(map[string]string)

	for _, item := range input {
		parts := strings.Split(item, ":")
		if len(parts) < 2 {
			continue
		}

		ip := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		ipPorts[ip] = append(ipPorts[ip], port)
		if len(parts) >= 3 && parts[2] != "" {
			ipHosts[ip] = parts[2]
		}
	}

	if len(ipPorts) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Nmap] Running service detection against %d IPs...\n", len(ipPorts))

	var results []engine.Result
	scannedCount := 0

	for ip, ports := range ipPorts {
		scannedCount++

		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = strconv.Itoa(p)
		}
		portList := strings.Join(portStrs, ",")

		fmt.Printf("[Nmap] (%d/%d) Scanning %s on %d ports...\n", scannedCount, len(ipPorts), ip, len(ports))

		cmd := exec.Command("nmap",
			"-sV",
			"-Pn",
			"-T4",
			"--open",
			"-p", portList,
			ip,
		)

		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("[Nmap] Scan failed for %s: %v\n", ip, err)
			continue
		}

		host := ipHosts[ip]
		portResults := parseNmapOutput(string(output), ip, host)
		results = append(results, portResults...)
	}

	fmt.Printf("[Nmap] Service detection finished, identified %d services\n", len(results))
	return results, nil
}

// parseNmapOutput parses open port lines from nmap output.
func parseNmapOutput(output string, ip string, host string) []engine.Result {
	var results []engine.Result

	// Example matched line:
	// "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu"
	portRegex := regexp.MustCompile(`(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		matches := portRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		port, _ := strconv.Atoi(matches[1])
		protocol := matches[2]
		service := matches[3]
		version := strings.TrimSpace(matches[4])

		results = append(results, engine.Result{
			Type: "port_service",
			Data: map[string]interface{}{
				"ip":       ip,
				"port":     port,
				"protocol": protocol,
				"service":  service,
				"version":  version,
				"domain":   host,
			},
		})
	}

	return results
}
