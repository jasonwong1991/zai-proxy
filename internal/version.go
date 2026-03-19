package internal

import (
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var (
	feVersion   string
	versionLock sync.RWMutex
)

func GetFeVersion() string {
	versionLock.RLock()
	defer versionLock.RUnlock()
	return feVersion
}

func fetchFeVersion() {
	req, err := http.NewRequest("GET", "https://chat.z.ai/", nil)
	if err != nil {
		LogError("Failed to create fe version request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	client := NewBrowserHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		LogError("Failed to fetch fe version: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		LogError("Failed to read fe version response: %v", err)
		return
	}

	re := regexp.MustCompile(`prod-fe-[\.\d]+`)
	match := re.FindString(string(body))
	if match != "" {
		versionLock.Lock()
		feVersion = match
		versionLock.Unlock()
		LogInfo("Updated fe version: %s", match)
	}
}

func StartVersionUpdater() {
	fetchFeVersion()

	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			fetchFeVersion()
		}
	}()
}
