package subdomain

import (
	"fmt"
	"sort"
	"strings"

	"hunter/internal/engine"
)

const (
	defaultDictWordLimit = 1500
	minDictWordLimit     = 100
	maxDictWordLimit     = 5000
)

// DictgenPlugin builds a compact custom dictionary from discovered subdomains.
type DictgenPlugin struct {
	maxWords int
}

// NewDictgenPlugin creates a dictionary generator plugin.
func NewDictgenPlugin(maxWords int) *DictgenPlugin {
	return &DictgenPlugin{maxWords: clampDictWordLimit(maxWords)}
}

// Name returns plugin name.
func (d *DictgenPlugin) Name() string {
	return "Dictgen"
}

// Execute generates dictionary words suitable for active brute-force.
func (d *DictgenPlugin) Execute(input []string) ([]engine.Result, error) {
	domains := normalizeDomains(input)
	wordScores := map[string]int{}

	for _, seed := range defaultSeedWords() {
		wordScores[seed] = 1
	}

	for _, domain := range domains {
		labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
		if len(labels) < 3 {
			continue
		}

		// Use all left-side labels as training corpus.
		for _, label := range labels[:len(labels)-2] {
			for _, token := range splitLabelTokens(label) {
				if !isValidWordToken(token) {
					continue
				}
				wordScores[token] += 2
			}
		}
	}

	words := rankWords(wordScores, d.maxWords)
	results := make([]engine.Result, 0, len(words))
	for _, word := range words {
		results = append(results, engine.Result{
			Type: "dict_word",
			Data: word,
		})
	}

	fmt.Printf("[Dictgen] Generated %d dictionary words (limit=%d)\n", len(results), d.maxWords)
	return results, nil
}

func clampDictWordLimit(v int) int {
	if v <= 0 {
		return defaultDictWordLimit
	}
	if v < minDictWordLimit {
		return minDictWordLimit
	}
	if v > maxDictWordLimit {
		return maxDictWordLimit
	}
	return v
}

func defaultSeedWords() []string {
	return []string{
		"api", "dev", "test", "stage", "staging", "uat", "pre", "prod", "beta", "alpha",
		"admin", "auth", "sso", "portal", "login", "app", "web", "m", "mobile",
		"cdn", "img", "static", "assets",
		"git", "gitlab", "github", "jira", "jenkins", "grafana", "kibana",
		"vpn", "gw", "gateway", "intranet", "internal", "ops", "monitor",
		"mail", "smtp", "imap", "pop", "mx",
		"db", "redis", "mysql", "pgsql", "cache", "mq",
	}
}

func splitLabelTokens(label string) []string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return nil
	}

	parts := strings.FieldsFunc(label, func(r rune) bool {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= '0' && r <= '9' {
			return false
		}
		return true
	})

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, "-")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isValidWordToken(token string) bool {
	if len(token) < 2 || len(token) > 24 {
		return false
	}
	for _, r := range token {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isDigit && r != '-' {
			return false
		}
	}
	return true
}

func rankWords(scores map[string]int, limit int) []string {
	type kv struct {
		Word  string
		Score int
	}

	items := make([]kv, 0, len(scores))
	for word, score := range scores {
		items = append(items, kv{Word: word, Score: score})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Score == items[j].Score {
			return items[i].Word < items[j].Word
		}
		return items[i].Score > items[j].Score
	})

	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, items[i].Word)
	}
	return out
}
