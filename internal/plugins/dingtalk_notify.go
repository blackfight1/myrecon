package plugins

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DingTalkNotifier sends simple recon notifications.
type DingTalkNotifier struct {
	enabled bool
	webhook string
	secret  string
	client  *http.Client
}

// NewDingTalkNotifierFromEnv creates a notifier from env.
// It reads webhook from DINGTALK_WEBHOOK.
func NewDingTalkNotifierFromEnv(enabled bool) *DingTalkNotifier {
	webhook := strings.TrimSpace(os.Getenv("DINGTALK_WEBHOOK"))
	secret := strings.TrimSpace(os.Getenv("DINGTALK_SECRET"))
	return &DingTalkNotifier{
		enabled: enabled && webhook != "",
		webhook: webhook,
		secret:  secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Enabled reports whether notifier is active.
func (n *DingTalkNotifier) Enabled() bool {
	return n != nil && n.enabled
}

// SendReconStart sends recon start notification.
func (n *DingTalkNotifier) SendReconStart(inputCount int, modules []string, dryRun bool) error {
	if !n.Enabled() {
		return nil
	}

	content := fmt.Sprintf(
		"[Hunter] Recon 开始\n输入数量: %d\n模块: %s\n模式: %s\n时间: %s",
		inputCount,
		strings.Join(modules, ","),
		map[bool]string{true: "dry-run", false: "normal"}[dryRun],
		time.Now().Format("2006-01-02 15:04:05"),
	)
	return n.sendText(content)
}

// SendReconEnd sends recon finish notification.
func (n *DingTalkNotifier) SendReconEnd(success bool, duration time.Duration, stats map[string]int, errMsg string) error {
	if !n.Enabled() {
		return nil
	}

	status := "成功"
	if !success {
		status = "失败"
	}

	content := fmt.Sprintf(
		"[Hunter] Recon 结束\n状态: %s\n耗时: %s\n子域名: %d\nWeb服务: %d\n端口: %d\n漏洞: %d\n截图: %d\n时间: %s",
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
		content += "\n错误: " + errMsg
	}

	return n.sendText(content)
}

func (n *DingTalkNotifier) sendText(content string) error {
	payload := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": content,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	requestURL, err := n.buildSignedURL()
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewBuffer(body))
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
		return fmt.Errorf("dingtalk notify failed with status: %s", resp.Status)
	}

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode dingtalk response: %v", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("dingtalk notify failed: errcode=%d errmsg=%s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

func (n *DingTalkNotifier) buildSignedURL() (string, error) {
	if n.secret == "" {
		return n.webhook, nil
	}

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	stringToSign := timestamp + "\n" + n.secret

	mac := hmac.New(sha256.New, []byte(n.secret))
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return "", fmt.Errorf("failed to sign dingtalk request: %v", err)
	}

	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	encodedSign := url.QueryEscape(sign)

	separator := "?"
	if strings.Contains(n.webhook, "?") {
		separator = "&"
	}
	return n.webhook + separator + "timestamp=" + timestamp + "&sign=" + encodedSign, nil
}
