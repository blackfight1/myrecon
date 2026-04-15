package plugins

import "time"

// Notifier defines a common notification contract across channels.
type Notifier interface {
	Enabled() bool
	SendReconStart(inputCount int, modules []string, dryRun bool) error
	SendReconEnd(success bool, duration time.Duration, stats map[string]int, errMsg string) error
	SendMonitorChanges(rootDomain string, changes map[string]int, highlights []string) error
	SendMonitorRunDigest(
		projectID, rootDomain string,
		runID uint,
		duration time.Duration,
		changes map[string]int,
		newAssetLines []string,
		portLines []string,
		omittedAssets int,
		omittedPorts int,
		aiSummary string,
	) error
}
