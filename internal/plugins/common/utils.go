package common

import (
	"os"
)

// CreateTempFile creates a temp file and writes lines into it.
func CreateTempFile(pattern string, lines []string) (string, error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}

	for _, line := range lines {
		if _, err := tmpFile.WriteString(line + "\n"); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return "", err
		}
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

// RemoveTempFile removes a temp file if it exists.
func RemoveTempFile(path string) {
	os.Remove(path)
}
