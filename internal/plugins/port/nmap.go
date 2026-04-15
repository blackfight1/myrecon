package port

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"sort"
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
func (n *NmapPlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	nmapBin, err := resolveNmapBinary()
	if err != nil {
		return nil, err
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
		if ip == "" || port <= 0 {
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
		ports = uniqueSortedPorts(ports)
		if len(ports) == 0 {
			continue
		}

		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = strconv.Itoa(p)
		}
		portList := strings.Join(portStrs, ",")

		fmt.Printf("[Nmap] (%d/%d) Scanning %s on %d ports...\n", scannedCount, len(ipPorts), ip, len(ports))

		cmd := exec.CommandContext(ctx, nmapBin,
			"-sV",
			"-Pn",
			"-T4",
			"-p", portList,
			"-oX", "-",
			ip,
		)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			if stderr.Len() > 0 {
				fmt.Printf("[Nmap] Scan failed for %s: %v | %s\n", ip, err, strings.TrimSpace(stderr.String()))
			} else {
				fmt.Printf("[Nmap] Scan failed for %s: %v\n", ip, err)
			}
			continue
		}

		host := ipHosts[ip]
		portResults, parseErr := parseNmapXMLOutput(output, ip, host)
		if parseErr != nil {
			fmt.Printf("[Nmap] Parse failed for %s: %v\n", ip, parseErr)
			continue
		}
		results = append(results, portResults...)
	}

	fmt.Printf("[Nmap] Service detection finished, identified %d services\n", len(results))
	return results, nil
}

func resolveNmapBinary() (string, error) {
	if p, err := exec.LookPath("nmap"); err == nil && strings.TrimSpace(p) != "" {
		return p, nil
	}
	// snap-installed nmap is commonly located here and may be missing from service PATH.
	fallbacks := []string{
		"/snap/bin/nmap",
		"/usr/bin/nmap",
		"/usr/local/bin/nmap",
	}
	for _, p := range fallbacks {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("nmap not found in PATH (also checked /snap/bin/nmap, /usr/bin/nmap, /usr/local/bin/nmap)")
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Items []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
	Service  nmapService   `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Tunnel    string `xml:"tunnel,attr"`
}

func parseNmapXMLOutput(output []byte, fallbackIP string, host string) ([]engine.Result, error) {
	var doc nmapRun
	if err := xml.Unmarshal(output, &doc); err != nil {
		return nil, err
	}

	var results []engine.Result
	for _, h := range doc.Hosts {
		ip := fallbackIP
		for _, addr := range h.Addresses {
			if addr.AddrType == "ipv4" && strings.TrimSpace(addr.Addr) != "" {
				ip = strings.TrimSpace(addr.Addr)
				break
			}
		}
		if ip == "" {
			continue
		}

		for _, p := range h.Ports.Items {
			if strings.ToLower(strings.TrimSpace(p.State.State)) != "open" {
				continue
			}
			if p.PortID <= 0 {
				continue
			}

			service := strings.TrimSpace(p.Service.Name)
			if service == "" {
				service = "unknown"
			}
			tunnel := strings.TrimSpace(p.Service.Tunnel)
			if tunnel != "" && !strings.Contains(service, "/") {
				service = tunnel + "/" + service
			}

			versionParts := make([]string, 0, 3)
			if s := strings.TrimSpace(p.Service.Product); s != "" {
				versionParts = append(versionParts, s)
			}
			if s := strings.TrimSpace(p.Service.Version); s != "" {
				versionParts = append(versionParts, s)
			}
			if s := strings.TrimSpace(p.Service.ExtraInfo); s != "" {
				versionParts = append(versionParts, "("+s+")")
			}

			results = append(results, engine.Result{
				Type: "port_service",
				Data: map[string]interface{}{
					"ip":       ip,
					"port":     p.PortID,
					"protocol": strings.TrimSpace(p.Protocol),
					"service":  service,
					"version":  strings.Join(versionParts, " "),
					"domain":   host,
				},
			})
		}
	}

	return results, nil
}

func uniqueSortedPorts(ports []int) []int {
	if len(ports) == 0 {
		return []int{}
	}
	seen := make(map[int]bool)
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
