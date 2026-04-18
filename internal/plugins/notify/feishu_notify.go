package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// FeishuNotifier sends recon notifications to Feishu bot webhook.
type FeishuNotifier struct {
	enabled bool
	webhook string
	client  *http.Client
}

// NewFeishuNotifierFromEnv creates a notifier from FEISHU_WEBHOOK.
func NewFeishuNotifierFromEnv(enabled bool) *FeishuNotifier {
	webhook := strings.TrimSpace(os.Getenv("FEISHU_WEBHOOK"))
	return &FeishuNotifier{
		enabled: enabled && webhook != "",
		webhook: webhook,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Enabled reports whether notifier is active.
func (n *FeishuNotifier) Enabled() bool {
	return n != nil && n.enabled
}

// SendReconStart sends recon start notification.
func (n *FeishuNotifier) SendReconStart(inputCount int, modules []string, dryRun bool) error {
	if !n.Enabled() {
		return nil
	}
	content := fmt.Sprintf(
		"[Hunter] Recon Start\nInputs: %d\nModules: %s\nMode: %s\nTime: %s",
		inputCount,
		strings.Join(modules, ","),
		map[bool]string{true: "dry-run", false: "normal"}[dryRun],
		time.Now().Format("2006-01-02 15:04:05"),
	)
	return n.sendText(content)
}

// SendReconEnd sends recon finish notification.
func (n *FeishuNotifier) SendReconEnd(success bool, duration time.Duration, stats map[string]int, errMsg string) error {
	if !n.Enabled() {
		return nil
	}
	status := "success"
	if !success {
		status = "failed"
	}
	content := fmt.Sprintf(
		"[Hunter] Recon End\nStatus: %s\nDuration: %s\nSubdomains: %d\nWeb services: %d\nPorts: %d\nVulnerabilities: %d\nScreenshots: %d\nTime: %s",
		status,
		duration.Round(time.Second).String(),
		stats["subdomains"],
		stats["web_services"],
		stats["ports"],
		stats["vulnerabilities"],
		stats["screenshots"],
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if errMsg != "" {
		content += "\nError: " + errMsg
	}
	return n.sendText(content)
}

// SendMonitorChanges sends monitor delta summary.
func (n *FeishuNotifier) SendMonitorChanges(rootDomain string, changes map[string]int, highlights []string) error {
	if !n.Enabled() {
		return nil
	}
	content := fmt.Sprintf(
		"[Hunter] Monitor Change Alert\nDomain: %s\nNew live subdomains: %d\nWeb changes: %d\nNew open ports: %d\nClosed ports: %d\nService changes: %d\nTime: %s",
		rootDomain,
		changes["new_live_subdomains"],
		changes["web_changed"],
		changes["port_opened"],
		changes["port_closed"],
		changes["service_changed"],
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if len(highlights) > 0 {
		content += "\nHighlights:\n- " + strings.Join(highlights, "\n- ")
	}
	return n.sendText(content)
}

// SendMonitorRunDigest sends compact monitor digest with low-noise formatting.
func (n *FeishuNotifier) SendMonitorRunDigest(
	projectID, rootDomain string,
	runID uint,
	duration time.Duration,
	changes map[string]int,
	newAssetLines []string,
	portLines []string,
	omittedAssets int,
	omittedPorts int,
	aiSummary string,
) error {
	if !n.Enabled() {
		return nil
	}

	var b strings.Builder
	b.WriteString("### [Hunter] Monitor Digest\n")
	b.WriteString(fmt.Sprintf("- Project: `%s`\n", safeInline(projectID)))
	b.WriteString(fmt.Sprintf("- Root Domain: `%s`\n", safeInline(rootDomain)))
	b.WriteString(fmt.Sprintf("- Run ID: `%d`\n", runID))
	b.WriteString(fmt.Sprintf("- Date: `%s`\n", time.Now().Format("2006-01-02")))
	b.WriteString(fmt.Sprintf("- Duration: `%s`\n", duration.Round(time.Second).String()))
	b.WriteString(fmt.Sprintf("- Changes: new_live=%d, web_changed=%d, port_opened=%d, port_closed=%d, service_changed=%d\n",
		changes["new_live"],
		changes["web_changed"],
		changes["port_opened"],
		changes["port_closed"],
		changes["service_changed"],
	))

	if strings.TrimSpace(aiSummary) != "" {
		b.WriteString("\n**AI Summary (noise-reduced)**\n")
		normalized := strings.ReplaceAll(aiSummary, "\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")
		lines := strings.Split(normalized, "\n")
		written := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if written >= 4 {
				b.WriteString("- ...\n")
				break
			}
			b.WriteString("- ")
			b.WriteString(safeMarkdownLine(line))
			b.WriteString("\n")
			written++
		}
	}

	if len(newAssetLines) > 0 {
		b.WriteString("\n**Web Assets (date | url | title | tech)**\n")
		for _, line := range newAssetLines {
			b.WriteString("- ")
			b.WriteString(safeMarkdownLine(line))
			b.WriteString("\n")
		}
		if omittedAssets > 0 {
			b.WriteString(fmt.Sprintf("- ... omitted %d more asset lines\n", omittedAssets))
		}
	}

	if len(portLines) > 0 {
		b.WriteString("\n**Port Changes (OPEN/CLOSED/CHANGED)**\n")
		for _, line := range portLines {
			b.WriteString("- ")
			b.WriteString(safeMarkdownLine(line))
			b.WriteString("\n")
		}
		if omittedPorts > 0 {
			b.WriteString(fmt.Sprintf("- ... omitted %d more port lines\n", omittedPorts))
		}
	}

	b.WriteString("\n> Generated at: ")
	b.WriteString(time.Now().Format("2006-01-02 15:04:05"))
	return n.sendMarkdown("Monitor Change Notification", b.String())
}

func (n *FeishuNotifier) sendText(content string) error {
	payload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": content,
		},
	}
	return n.doSend(payload)
}

func (n *FeishuNotifier) sendMarkdown(title, text string) error {
	// Keep payload simple and stable across Feishu tenants.
	payload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": "[" + title + "]\n" + text,
		},
	}
	return n.doSend(payload)
}

func (n *FeishuNotifier) doSend(payload map[string]interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.webhook, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("feishu notify failed with status: %s", resp.Status)
	}
	return checkFeishuResponse(resp.Body)
}

func checkFeishuResponse(body io.Reader) error {
	var result struct {
		Code          int    `json:"code"`
		Msg           string `json:"msg"`
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		// Some proxies may return empty body on success.
		return nil
	}
	if result.Code != 0 {
		return fmt.Errorf("feishu notify failed: code=%d msg=%s", result.Code, result.Msg)
	}
	if result.StatusCode != 0 {
		return fmt.Errorf("feishu notify failed: status_code=%d status_message=%s", result.StatusCode, result.StatusMessage)
	}
	return nil
}

func safeInline(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, "`", "")
}

func safeMarkdownLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

