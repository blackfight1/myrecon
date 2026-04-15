package common

import (
	"regexp"
	"sort"
	"strings"
)

var (
	wordSplitRegex = regexp.MustCompile(`[^a-z0-9]+`)
	wordValidRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)
)

var defaultWordBlacklist = map[string]bool{
	"www":          true,
	"mail":         true,
	"ftp":          true,
	"autodiscover": true,
	"cpanel":       true,
	"webmail":      true,
	"localhost":    true,
}

// BuildBruteforceWordlist builds an active subdomain wordlist from observed subdomains.
// It intentionally avoids any model/tool dependency so scan flows remain deterministic.
func BuildBruteforceWordlist(passiveSubdomains, rootDomains []string, maxWords int) []string {
	if maxWords <= 0 {
		maxWords = 800
	}
	if maxWords > 100000 {
		maxWords = 100000
	}

	roots := normalizeRootDomains(rootDomains)
	scores := make(map[string]int, 1024)

	for _, raw := range passiveSubdomains {
		host := normalizeHost(raw)
		if host == "" {
			continue
		}
		relative := relativePart(host, roots)
		if relative == "" {
			continue
		}
		labels := strings.Split(relative, ".")
		for i, label := range labels {
			baseWeight := 4
			if i == 0 {
				baseWeight = 6
			}
			addWordScore(scores, label, baseWeight)

			parts := splitWordParts(label)
			for _, part := range parts {
				addWordScore(scores, part, baseWeight+2)
			}
			if len(parts) >= 2 {
				addWordScore(scores, strings.Join(parts, "-"), baseWeight+1)
			}
		}
		if len(labels) >= 2 {
			addWordScore(scores, labels[0]+"-"+labels[1], 3)
		}
	}

	type pair struct {
		word  string
		score int
	}
	ordered := make([]pair, 0, len(scores))
	for w, s := range scores {
		if s <= 0 {
			continue
		}
		ordered = append(ordered, pair{word: w, score: s})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].score != ordered[j].score {
			return ordered[i].score > ordered[j].score
		}
		return ordered[i].word < ordered[j].word
	})

	out := make([]string, 0, minInt(len(ordered), maxWords))
	for _, item := range ordered {
		if len(out) >= maxWords {
			break
		}
		out = append(out, item.word)
	}
	return out
}

// NormalizeBruteforceWords sanitizes arbitrary candidates into valid dnsx wordlist entries.
// It keeps input order, deduplicates results and applies a safe upper bound.
func NormalizeBruteforceWords(rawWords []string, maxWords int) []string {
	if maxWords <= 0 {
		maxWords = 800
	}
	if maxWords > 100000 {
		maxWords = 100000
	}
	out := make([]string, 0, minInt(len(rawWords), maxWords))
	seen := make(map[string]bool, minInt(len(rawWords), maxWords))
	appendWord := func(raw string) {
		if len(out) >= maxWords {
			return
		}
		word := strings.ToLower(strings.TrimSpace(raw))
		word = strings.Trim(word, "._-")
		if !isUsefulWord(word) {
			return
		}
		if seen[word] {
			return
		}
		seen[word] = true
		out = append(out, word)
	}

	for _, item := range rawWords {
		if len(out) >= maxWords {
			break
		}
		segments := strings.FieldsFunc(item, func(r rune) bool {
			switch r {
			case '\n', '\r', '\t', ' ', ',', ';', '|':
				return true
			default:
				return false
			}
		})
		if len(segments) == 0 {
			segments = []string{item}
		}
		for _, seg := range segments {
			if len(out) >= maxWords {
				break
			}
			seg = strings.ToLower(strings.TrimSpace(seg))
			if seg == "" {
				continue
			}
			seg = strings.TrimPrefix(seg, "http://")
			seg = strings.TrimPrefix(seg, "https://")
			if idx := strings.Index(seg, "/"); idx >= 0 {
				seg = seg[:idx]
			}
			if idx := strings.Index(seg, ":"); idx >= 0 {
				seg = seg[:idx]
			}
			seg = strings.Trim(seg, "._-")
			if seg == "" {
				continue
			}
			if idx := strings.Index(seg, "."); idx >= 0 {
				seg = seg[:idx]
			}
			appendWord(seg)
			if len(out) >= maxWords {
				break
			}
			parts := splitWordParts(seg)
			for _, part := range parts {
				appendWord(part)
				if len(out) >= maxWords {
					break
				}
			}
			if len(out) >= maxWords {
				break
			}
			if len(parts) >= 2 {
				appendWord(strings.Join(parts, "-"))
			}
		}
	}
	return out
}

// MergeBruteforceWordlists merges two wordlists with stable order and deduplication.
func MergeBruteforceWordlists(primary, secondary []string, maxWords int) []string {
	if maxWords <= 0 {
		maxWords = 800
	}
	if maxWords > 100000 {
		maxWords = 100000
	}
	out := make([]string, 0, minInt(len(primary)+len(secondary), maxWords))
	seen := make(map[string]bool, minInt(len(primary)+len(secondary), maxWords))
	appendWord := func(raw string) {
		if len(out) >= maxWords {
			return
		}
		word := strings.ToLower(strings.TrimSpace(raw))
		word = strings.Trim(word, "._-")
		if !isUsefulWord(word) {
			return
		}
		if seen[word] {
			return
		}
		seen[word] = true
		out = append(out, word)
	}
	for _, w := range primary {
		appendWord(w)
		if len(out) >= maxWords {
			return out
		}
	}
	for _, w := range secondary {
		appendWord(w)
		if len(out) >= maxWords {
			return out
		}
	}
	return out
}

func normalizeRootDomains(rootDomains []string) []string {
	seen := make(map[string]bool, len(rootDomains))
	out := make([]string, 0, len(rootDomains))
	for _, raw := range rootDomains {
		h := normalizeHost(raw)
		if h == "" {
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func relativePart(host string, roots []string) string {
	for _, root := range roots {
		if host == root {
			return ""
		}
		suffix := "." + root
		if strings.HasSuffix(host, suffix) {
			return strings.TrimSuffix(host, suffix)
		}
	}
	erd := EffectiveRootDomain(host)
	if erd != "" && erd != host {
		suffix := "." + erd
		if strings.HasSuffix(host, suffix) {
			return strings.TrimSuffix(host, suffix)
		}
	}
	return host
}

func splitWordParts(label string) []string {
	parts := wordSplitRegex.Split(strings.ToLower(strings.TrimSpace(label)), -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, "-")
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func addWordScore(scores map[string]int, raw string, weight int) {
	word := strings.ToLower(strings.TrimSpace(raw))
	word = strings.Trim(word, ".-_")
	if !isUsefulWord(word) {
		return
	}
	scores[word] += weight
}

func isUsefulWord(word string) bool {
	if len(word) < 2 || len(word) > 40 {
		return false
	}
	if defaultWordBlacklist[word] {
		return false
	}
	if strings.IndexFunc(word, func(r rune) bool { return r < '0' || (r > '9' && r < 'a') || r > 'z' }) == -1 {
		onlyDigits := true
		for _, r := range word {
			if r < '0' || r > '9' {
				onlyDigits = false
				break
			}
		}
		if onlyDigits {
			return false
		}
	}
	return wordValidRegex.MatchString(word)
}

func normalizeHost(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	if idx := strings.Index(v, "/"); idx != -1 {
		v = v[:idx]
	}
	if idx := strings.Index(v, ":"); idx != -1 {
		v = v[:idx]
	}
	return strings.Trim(v, ".")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
