package port

import (
	"database/sql"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hunter/internal/engine"
	plugincommon "hunter/internal/plugins/common"

	_ "modernc.org/sqlite"
)

// TscanPortPlugin performs port discovery and fingerprinting via TscanClient.
type TscanPortPlugin struct {
	ports       string
	extraPorts  string
	concurrency int
	timeoutSec  int
}

type tscanIPScanRow struct {
	Host     string
	Port     int
	Protocol string
	Title    string
	Banner   string
	Status   string
}

// NewTscanPortPlugin creates a TscanClient-backed port scanner.
func NewTscanPortPlugin() *TscanPortPlugin {
	return &TscanPortPlugin{
		ports:       strings.TrimSpace(os.Getenv("TSCANCLIENT_PORTS")),
		extraPorts:  strings.TrimSpace(os.Getenv("TSCANCLIENT_EXTRA_PORTS")),
		concurrency: envIntWithBounds("TSCANCLIENT_PORT_CONCURRENCY", 600, 1, 5000),
		timeoutSec:  envIntWithBounds("TSCANCLIENT_TIMEOUT_SEC", 3, 1, 30),
	}
}

// Name returns plugin name.
func (t *TscanPortPlugin) Name() string {
	return "TscanPort"
}

// Execute runs TscanClient in an isolated workdir and converts ipscan rows into
// the existing open_port + port_service result contract.
func (t *TscanPortPlugin) Execute(input []string) ([]engine.Result, error) {
	bin, err := resolveTscanBinary()
	if err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	ipHosts, ipTargets := t.resolveTargets(input)
	if len(ipTargets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[TscanPort] Scanning %d IPs resolved from %d targets...\n", len(ipTargets), len(input))

	workDir, err := os.MkdirTemp("", "myrecon_tscan_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create tscan workdir: %v", err)
	}
	defer os.RemoveAll(workDir)

	targetFile, err := plugincommon.CreateTempFile("tscan_targets_*.txt", ipTargets)
	if err != nil {
		return nil, fmt.Errorf("failed to create tscan target file: %v", err)
	}
	defer plugincommon.RemoveTempFile(targetFile)

	projectName := "myrecon-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	outputPath := filepath.Join(workDir, "port-output.txt")

	args := []string{
		"-m", "port",
		"-hf", targetFile,
		"-pr", projectName,
		"-o", outputPath,
		"-nocolor",
		"-t", strconv.Itoa(t.concurrency),
		"-time", strconv.Itoa(t.timeoutSec),
	}
	if t.ports != "" {
		args = append(args, "-p", t.ports)
	}
	if t.extraPorts != "" {
		args = append(args, "-pa", t.extraPorts)
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = workDir
	output, runErr := cmd.CombinedOutput()

	rows, parseErr := readTscanIPScan(filepath.Join(workDir, "config.db"), projectName)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("tscanclient execution failed: %v; parse failed: %v; output=%s", runErr, parseErr, compactCommandOutput(string(output), 320))
		}
		return nil, fmt.Errorf("failed to parse tscanclient output: %v", parseErr)
	}
	if runErr != nil && len(rows) == 0 {
		return nil, fmt.Errorf("tscanclient execution failed: %v | output=%s", runErr, compactCommandOutput(string(output), 320))
	}
	if runErr != nil {
		fmt.Printf("[TscanPort] Command finished with warning: %v\n", runErr)
	}

	results := buildTscanResults(rows, ipHosts)
	fmt.Printf("[TscanPort] Scan completed, found %d open ports\n", countResultType(results, "open_port"))
	return results, nil
}

func resolveTscanBinary() (string, error) {
	candidates := []string{
		"tscanclient",
		"TscanClient",
		"TscanClient_linux_amd64_v2.9.5",
		"/usr/local/bin/tscanclient",
		"/root/tools/tscanclient/tscanclient",
		"/root/tools/tscanclient/TscanClient_linux_amd64_v2.9.5",
	}
	for _, candidate := range candidates {
		if p, err := exec.LookPath(candidate); err == nil && strings.TrimSpace(p) != "" {
			return p, nil
		}
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("tscanclient not found in PATH (also checked /usr/local/bin/tscanclient and /root/tools/tscanclient)")
}

func (t *TscanPortPlugin) resolveTargets(input []string) (map[string][]string, []string) {
	ipHosts := make(map[string]map[string]bool)
	ipSet := make(map[string]bool)

	for _, raw := range input {
		host := normalizeTscanTarget(raw)
		if host == "" {
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			normalizedIP := normalizeIPv4(ip.String())
			if normalizedIP == "" {
				continue
			}
			ipSet[normalizedIP] = true
			if ipHosts[normalizedIP] == nil {
				ipHosts[normalizedIP] = map[string]bool{}
			}
			ipHosts[normalizedIP][host] = true
			continue
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			normalizedIP := normalizeIPv4(ip.String())
			if normalizedIP == "" {
				continue
			}
			ipSet[normalizedIP] = true
			if ipHosts[normalizedIP] == nil {
				ipHosts[normalizedIP] = map[string]bool{}
			}
			ipHosts[normalizedIP][host] = true
		}
	}

	resolvedHosts := make(map[string][]string, len(ipHosts))
	for ip, hosts := range ipHosts {
		list := make([]string, 0, len(hosts))
		for host := range hosts {
			list = append(list, host)
		}
		sort.Strings(list)
		resolvedHosts[ip] = list
	}

	ipTargets := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipTargets = append(ipTargets, ip)
	}
	sort.Strings(ipTargets)

	return resolvedHosts, ipTargets
}

func normalizeTscanTarget(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := neturl.Parse(value); err == nil {
			value = parsed.Hostname()
		}
	}
	value = strings.TrimSuffix(value, ".")
	return value
}

func normalizeIPv4(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ""
}

func readTscanIPScan(dbPath, projectName string) ([]tscanIPScanRow, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("config.db not found: %v", err)
	}

	dbConn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer dbConn.Close()

	rows, err := dbConn.Query(`
		SELECT COALESCE(Host, ''), COALESCE(Port, 0), COALESCE(Protocol, ''), COALESCE(Title, ''), COALESCE(Banner, ''), COALESCE(Status, '')
		FROM ipscan
		WHERE Project = ?
	`, projectName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []tscanIPScanRow
	for rows.Next() {
		var row tscanIPScanRow
		if err := rows.Scan(&row.Host, &row.Port, &row.Protocol, &row.Title, &row.Banner, &row.Status); err != nil {
			return nil, err
		}
		row.Host = normalizeIPv4(row.Host)
		if row.Host == "" || row.Port <= 0 {
			continue
		}
		if status := strings.ToLower(strings.TrimSpace(row.Status)); status != "" && status != "open" {
			continue
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func buildTscanResults(rows []tscanIPScanRow, ipHosts map[string][]string) []engine.Result {
	results := make([]engine.Result, 0, len(rows)*2)
	seenOpen := make(map[string]bool, len(rows))
	seenService := make(map[string]bool, len(rows))

	for _, row := range rows {
		hosts := ipHosts[row.Host]
		if len(hosts) == 0 {
			hosts = []string{""}
		}

		protocol := "tcp"
		service := deriveTscanService(row.Protocol, row.Port, row.Title, row.Banner)
		version := deriveTscanVersion(service, row.Title, row.Banner)
		banner := deriveTscanBanner(service, row.Title, row.Banner)

		for _, host := range hosts {
			openKey := fmt.Sprintf("%s|%d|%s", row.Host, row.Port, host)
			if !seenOpen[openKey] {
				seenOpen[openKey] = true
				results = append(results, engine.Result{
					Type: "open_port",
					Data: map[string]interface{}{
						"host":     host,
						"domain":   host,
						"ip":       row.Host,
						"port":     row.Port,
						"protocol": protocol,
					},
				})
			}

			if service == "" && version == "" && banner == "" {
				continue
			}

			serviceKey := fmt.Sprintf("%s|%d|%s|%s|%s|%s", row.Host, row.Port, host, service, version, banner)
			if seenService[serviceKey] {
				continue
			}
			seenService[serviceKey] = true

			results = append(results, engine.Result{
				Type: "port_service",
				Data: map[string]interface{}{
					"domain":   host,
					"host":     host,
					"ip":       row.Host,
					"port":     row.Port,
					"protocol": protocol,
					"service":  service,
					"version":  version,
					"banner":   banner,
				},
			})
		}
	}

	return results
}

func normalizeTscanService(raw string) string {
	service := strings.ToLower(strings.TrimSpace(raw))
	service = strings.ReplaceAll(service, "\\", "/")
	service = strings.TrimPrefix(service, "tcp/")
	service = strings.TrimPrefix(service, "udp/")
	service = strings.Trim(service, " /-_")
	switch service {
	case "www", "http service":
		return "http"
	case "https service":
		return "https"
	default:
		return service
	}
}

func deriveTscanService(protocol string, port int, title, banner string) string {
	rawService := normalizeTscanService(protocol)
	signal := strings.ToLower(strings.Join([]string{strings.TrimSpace(banner), strings.TrimSpace(title)}, " "))
	service := rawService

	if isHTTPFamilyService(rawService) {
		if shouldTreatAsHTTPS(rawService, signal, port) {
			return "https"
		}
		return "http"
	}

	if service == "" || service == "unknown" {
		service = inferServiceFromSignal(signal, port)
	}
	if service == "" || service == "unknown" {
		service = inferServiceFromPort(port)
	}
	if service == "" {
		return "unknown"
	}
	return service
}

func deriveTscanVersion(service, title, banner string) string {
	title = compactCommandOutput(title, 200)
	banner = compactCommandOutput(banner, 240)

	if service == "http" || service == "https" {
		if server, version := extractHTTPFingerprint(title, banner); server != "" {
			if version != "" {
				return server + " " + version
			}
			return server
		}
	}

	for _, source := range []string{banner, title} {
		if source == "" {
			continue
		}
		if version := extractVersionForService(service, source); version != "" {
			return version
		}
	}

	if title != "" && !looksLikeHTTPTitle(service, title) && !looksLikeURL(title) && looksLikeVersionedProduct(title) {
		return title
	}

	if banner != "" && looksLikeVersionedProduct(banner) {
		return banner
	}

	return ""
}

func looksLikeHTTPTitle(service, title string) bool {
	if service != "http" && service != "https" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(title))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	return false
}

func deriveTscanBanner(service, title, banner string) string {
	banner = compactCommandOutput(banner, 280)
	title = compactCommandOutput(title, 160)

	if looksLikeURL(title) {
		title = ""
	}

	switch service {
	case "http", "https":
		parts := make([]string, 0, 3)
		server, version := extractHTTPFingerprint(title, banner)
		if server != "" {
			if version != "" {
				parts = append(parts, fmt.Sprintf("server=%s/%s", server, version))
			} else {
				parts = append(parts, "server="+server)
			}
		}
		if title != "" && !looksLikeVersionedProduct(title) && !looksLikeHTTPInfraText(title) {
			parts = append(parts, "title="+title)
		}
		rawBanner := cleanupHTTPBannerRemainder(banner)
		if rawBanner != "" && !containsAnyFold(rawBanner, parts...) {
			parts = append(parts, "raw="+rawBanner)
		}
		return compactCommandOutput(strings.Join(parts, " | "), 320)
	default:
		switch {
		case banner != "":
			return banner
		case title != "" && !looksLikeVersionedProduct(title):
			return title
		default:
			return ""
		}
	}
}

func inferServiceFromSignal(signal string, port int) string {
	type keywordRule struct {
		service  string
		keywords []string
	}
	rules := []keywordRule{
		{service: "https", keywords: []string{"https", "tls", "ssl certificate", "x509"}},
		{service: "http", keywords: []string{"http", "nginx", "apache", "iis", "tomcat", "jetty", "spring boot", "openresty", "weblogic", "jboss"}},
		{service: "ssh", keywords: []string{"openssh", "dropbear", "ssh-2.0", "ssh"}},
		{service: "mysql", keywords: []string{"mysql", "mariadb"}},
		{service: "redis", keywords: []string{"redis"}},
		{service: "postgresql", keywords: []string{"postgresql", "postgres"}},
		{service: "mongodb", keywords: []string{"mongodb"}},
		{service: "ftp", keywords: []string{"ftp", "vsftpd", "proftpd", "filezilla server"}},
		{service: "smb", keywords: []string{"smb", "microsoft-ds", "netbios", "samba"}},
		{service: "rdp", keywords: []string{"rdp", "remote desktop", "terminal services"}},
		{service: "ldap", keywords: []string{"ldap"}},
		{service: "smtp", keywords: []string{"smtp", "postfix", "exim", "sendmail"}},
		{service: "imap", keywords: []string{"imap", "dovecot"}},
		{service: "pop3", keywords: []string{"pop3"}},
		{service: "dns", keywords: []string{"domain name service", "bind"}},
		{service: "kubernetes", keywords: []string{"kubernetes"}},
		{service: "docker", keywords: []string{"docker"}},
		{service: "elasticsearch", keywords: []string{"elasticsearch"}},
		{service: "kibana", keywords: []string{"kibana"}},
		{service: "memcached", keywords: []string{"memcached"}},
	}

	for _, rule := range rules {
		for _, keyword := range rule.keywords {
			if strings.Contains(signal, keyword) {
				if rule.service == "http" && isLikelyHTTPSPort(port) && !strings.Contains(signal, "http/1.") && !strings.Contains(signal, "http/2") {
					return "https"
				}
				return rule.service
			}
		}
	}
	return ""
}

func isHTTPFamilyService(service string) bool {
	switch service {
	case "http", "https", "nginx", "apache", "apache httpd", "microsoft-iis", "iis",
		"openresty", "tomcat", "jetty", "caddy", "gunicorn", "uvicorn", "envoy",
		"traefik", "weblogic", "jboss", "wildfly", "spring boot":
		return true
	default:
		return false
	}
}

func shouldTreatAsHTTPS(service, signal string, port int) bool {
	if service == "https" {
		return true
	}
	if strings.Contains(signal, "https") || strings.Contains(signal, "tls") || strings.Contains(signal, "ssl") || strings.Contains(signal, "x509") {
		return true
	}
	if service == "http" && (strings.Contains(signal, "http/1.") || strings.Contains(signal, "http/2")) {
		return false
	}
	return isLikelyHTTPSPort(port)
}

func inferServiceFromPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 25, 465, 587:
		return "smtp"
	case 53:
		return "dns"
	case 80, 81, 88, 8000, 8001, 8080, 8081, 8088, 8888, 9000, 9090:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 389, 636:
		return "ldap"
	case 443, 4443, 5443, 6443, 7443, 8443, 9443:
		return "https"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2375, 2376:
		return "docker"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5601:
		return "kibana"
	case 6379:
		return "redis"
	case 8006:
		return "https"
	case 9200:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 27017:
		return "mongodb"
	default:
		return ""
	}
}

func extractVersionForService(service, source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}

	patterns := serviceVersionPatterns(service)
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(source)
		if len(matches) < 2 {
			continue
		}
		version := strings.Trim(matches[1], " ()[]")
		if version != "" {
			return version
		}
	}

	return ""
}

func serviceVersionPatterns(service string) []*regexp.Regexp {
	must := func(pattern string) *regexp.Regexp {
		return regexp.MustCompile(pattern)
	}

	common := []*regexp.Regexp{
		must(`(?i)\bv(?:ersion)?[ =:/-]*([0-9][0-9a-z._-]*)\b`),
		must(`(?i)\b([0-9]+\.[0-9][0-9a-z._-]*)\b`),
	}

	switch service {
	case "ssh":
		return append([]*regexp.Regexp{
			must(`(?i)\bopenssh[_ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bdropbear[_ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "http", "https":
		return append([]*regexp.Regexp{
			must(`(?i)\bnginx/([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bapache(?: httpd)?[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bmicrosoft-iis/([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bopenresty/([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bjetty(?:\([^)]+\))?[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\btomcat[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bcaddy[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bgunicorn[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\buvicorn[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\benvoy[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\btraefik[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bspring boot[ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "mysql":
		return append([]*regexp.Regexp{
			must(`(?i)\bmysql[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bmariadb[ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "postgresql":
		return append([]*regexp.Regexp{
			must(`(?i)\bpostgres(?:ql)?[ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "redis":
		return append([]*regexp.Regexp{
			must(`(?i)\bredis(?: server)?[ =:/-]*v?([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "mongodb":
		return append([]*regexp.Regexp{
			must(`(?i)\bmongodb[ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	case "ftp":
		return append([]*regexp.Regexp{
			must(`(?i)\bvsftpd[ /-]*([0-9][0-9a-z._-]*)\b`),
			must(`(?i)\bproftpd[ /-]*([0-9][0-9a-z._-]*)\b`),
		}, common...)
	default:
		return common
	}
}

type httpFingerprint struct {
	Server  string
	Version string
}

func extractHTTPFingerprint(title, banner string) (string, string) {
	for _, source := range []string{banner, title} {
		if fp := parseHTTPFingerprintFromText(source); fp.Server != "" {
			return fp.Server, fp.Version
		}
	}
	return "", ""
}

func parseHTTPFingerprintFromText(source string) httpFingerprint {
	source = strings.TrimSpace(source)
	if source == "" {
		return httpFingerprint{}
	}

	patterns := []struct {
		server string
		regex  *regexp.Regexp
	}{
		{server: "tomcat", regex: regexp.MustCompile(`(?i)\btomcat(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "weblogic", regex: regexp.MustCompile(`(?i)\bweblogic(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "jboss", regex: regexp.MustCompile(`(?i)\bjboss(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "wildfly", regex: regexp.MustCompile(`(?i)\bwildfly(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "openresty", regex: regexp.MustCompile(`(?i)\bopenresty(?:/([0-9][0-9a-z._-]*))?\b`)},
		{server: "nginx", regex: regexp.MustCompile(`(?i)\bnginx(?:/([0-9][0-9a-z._-]*))?\b`)},
		{server: "jetty", regex: regexp.MustCompile(`(?i)\bjetty(?:\([^)]+\))?(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "caddy", regex: regexp.MustCompile(`(?i)\bcaddy(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "gunicorn", regex: regexp.MustCompile(`(?i)\bgunicorn(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "uvicorn", regex: regexp.MustCompile(`(?i)\buvicorn(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "envoy", regex: regexp.MustCompile(`(?i)\benvoy(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "traefik", regex: regexp.MustCompile(`(?i)\btraefik(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "spring-boot", regex: regexp.MustCompile(`(?i)\bspring boot(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
		{server: "iis", regex: regexp.MustCompile(`(?i)\bmicrosoft-iis(?:/([0-9][0-9a-z._-]*))?\b`)},
		{server: "apache", regex: regexp.MustCompile(`(?i)\bapache(?: httpd)?(?:[ /-]*([0-9][0-9a-z._-]*))?\b`)},
	}

	for _, pattern := range patterns {
		matches := pattern.regex.FindStringSubmatch(source)
		if len(matches) == 0 {
			continue
		}
		version := ""
		if len(matches) > 1 {
			version = strings.TrimSpace(matches[1])
		}
		return httpFingerprint{Server: pattern.server, Version: version}
	}

	return httpFingerprint{}
}

func looksLikeURL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func looksLikeHTTPInfraText(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	keywords := []string{
		"nginx", "apache", "microsoft-iis", "openresty", "tomcat", "jetty",
		"caddy", "gunicorn", "uvicorn", "envoy", "traefik", "spring boot",
		"http/", "https", "welcome to nginx", "apache2 ubuntu default page",
	}
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func cleanupHTTPBannerRemainder(banner string) string {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return ""
	}
	lower := strings.ToLower(banner)
	if strings.HasPrefix(lower, "server=") || strings.HasPrefix(lower, "title=") || strings.HasPrefix(lower, "raw=") {
		return banner
	}
	if fp := parseHTTPFingerprintFromText(banner); fp.Server != "" {
		exact := fp.Server
		if fp.Version != "" {
			exact = fp.Server + "/" + fp.Version
		}
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(exact))
		banner = strings.TrimSpace(pattern.ReplaceAllString(banner, ""))
	}
	banner = strings.Trim(banner, " |-_/")
	return banner
}

func containsAnyFold(value string, items ...string) bool {
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	if lowerValue == "" {
		return false
	}
	for _, item := range items {
		lowerItem := strings.ToLower(strings.TrimSpace(item))
		if lowerItem != "" && strings.Contains(lowerItem, lowerValue) {
			return true
		}
	}
	return false
}

func looksLikeVersionedProduct(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return regexp.MustCompile(`(?i)[a-z][a-z0-9 ./_-]*\b[0-9]+\.[0-9]`).MatchString(value)
}

func isLikelyHTTPSPort(port int) bool {
	switch port {
	case 443, 4443, 5443, 6443, 7443, 8443, 9443:
		return true
	default:
		return false
	}
}

func compactCommandOutput(value string, maxLen int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}

func countResultType(results []engine.Result, resultType string) int {
	total := 0
	for _, item := range results {
		if item.Type == resultType {
			total++
		}
	}
	return total
}

func envIntWithBounds(key string, defaultVal, minVal, maxVal int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultVal
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultVal
	}
	if value < minVal {
		return minVal
	}
	if value > maxVal {
		return maxVal
	}
	return value
}
