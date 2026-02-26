package plugins

import (
	"os"
)

// createTempFile 创建临时文件并写入内容
func createTempFile(pattern string, lines []string) (string, error) {
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

// removeTempFile 删除临时文件
func removeTempFile(path string) {
	os.Remove(path)
}
