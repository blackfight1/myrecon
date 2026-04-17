package plugins

import (
	"hunter/internal/engine"
	"hunter/internal/plugins/notify"
	pluginport "hunter/internal/plugins/port"
	"hunter/internal/plugins/subdomain"
	"hunter/internal/plugins/vuln"
	"hunter/internal/plugins/web"
)

type FeishuNotifier = notify.FeishuNotifier

func NewFeishuNotifierFromEnv(enabled bool) *FeishuNotifier {
	return notify.NewFeishuNotifierFromEnv(enabled)
}

func NewSubfinderPlugin(batchMode bool) engine.Scanner {
	return subdomain.NewSubfinderPlugin(batchMode)
}

func NewChaosPlugin(batchMode bool) engine.Scanner {
	return subdomain.NewChaosPlugin(batchMode)
}

func NewBBOTPlugin(passiveOnly bool) engine.Scanner {
	return subdomain.NewBBOTPlugin(passiveOnly)
}

func NewFindomainPlugin() engine.Scanner {
	return subdomain.NewFindomainPlugin()
}

func NewShosubgoPlugin() engine.Scanner {
	return subdomain.NewShosubgoPlugin()
}

func NewDictgenPlugin(maxWords int) engine.Scanner {
	return subdomain.NewDictgenPlugin(maxWords)
}

func NewDNSXBruteforcePlugin(rootDomains []string, resolversFile string) engine.Scanner {
	return subdomain.NewDNSXBruteforcePlugin(rootDomains, resolversFile)
}

func NewHttpxPlugin() engine.Scanner {
	return web.NewHttpxPlugin()
}

func NewGowitnessPlugin(baseDir string) engine.Scanner {
	return web.NewGowitnessPlugin(baseDir)
}

func NewNaabuPlugin() engine.Scanner {
	return pluginport.NewNaabuPlugin()
}

func NewNmapPlugin() engine.Scanner {
	return pluginport.NewNmapPlugin()
}

func NewTscanPortPlugin() engine.Scanner {
	return pluginport.NewTscanPortPlugin()
}

func NewNucleiPlugin() engine.Scanner {
	return vuln.NewNucleiPlugin()
}

func NewCorsPlugin() engine.Scanner {
	return vuln.NewCorsPlugin()
}

func NewSubTakeoverPlugin() engine.Scanner {
	return vuln.NewSubTakeoverPlugin()
}

func StartReportServer(baseDir, rootDomain, host string, port int) error {
	return web.StartReportServer(baseDir, rootDomain, host, port)
}

func ListScreenshotDomains(baseDir string) ([]string, error) {
	return web.ListScreenshotDomains(baseDir)
}

// ScreenshotItem re-exports web.ScreenshotItem.
type ScreenshotItem = web.ScreenshotItem

func ListScreenshots(baseDir, rootDomain string) ([]ScreenshotItem, error) {
	return web.ListScreenshots(baseDir, rootDomain)
}

func InvalidateScreenshotCache(baseDir, rootDomain string) {
	web.InvalidateScreenshotCache(baseDir, rootDomain)
}

func ExtractRootDomain(subdomain string) string {
	return web.ExtractRootDomain(subdomain)
}
