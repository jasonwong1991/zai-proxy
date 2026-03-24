package internal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	url_pkg "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

func extractLatestUserContent(messages []Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			text, _ := messages[i].ParseContent()
			return text
		}
	}
	return ""
}

func extractAllImageURLs(messages []Message) []string {
	var allImageURLs []string
	for _, msg := range messages {
		_, imageURLs := msg.ParseContent()
		allImageURLs = append(allImageURLs, imageURLs...)
	}
	return allImageURLs
}

// mergeSystemMessages 将所有 system 消息的文本合并到第一条 user 消息中，
// 因为上游 z.ai 不支持 system 角色。
func mergeSystemMessages(messages []Message) []Message {
	var systemParts []string
	var filtered []Message
	for _, msg := range messages {
		if msg.Role == "system" {
			text, _ := msg.ParseContent()
			if text != "" {
				systemParts = append(systemParts, text)
			}
		} else {
			filtered = append(filtered, msg)
		}
	}

	if len(systemParts) == 0 {
		return messages
	}

	systemText := strings.Join(systemParts, "\n")

	for i, msg := range filtered {
		if msg.Role == "user" {
			text, imageURLs := msg.ParseContent()
			newText := systemText + "\n\n" + text
			if len(imageURLs) == 0 {
				filtered[i].Content = newText
			} else {
				// 多模态消息：重建 content，将系统提示词加到文本前
				var newContent []interface{}
				newContent = append(newContent, map[string]interface{}{
					"type": "text",
					"text": newText,
				})
				for _, imgURL := range imageURLs {
					newContent = append(newContent, map[string]interface{}{
						"type": "image_url",
						"image_url": map[string]interface{}{
							"url": imgURL,
						},
					})
				}
				filtered[i].Content = newContent
			}
			return filtered
		}
	}

	// 没有 user 消息，将系统提示词作为第一条 user 消息
	return append([]Message{{Role: "user", Content: systemText}}, filtered...)
}

// createChat 调用 z.ai 的 /api/v1/chats/new 创建会话，返回 chat_id
func createChat(token, model, msgID, content string, enableThinking, autoWebSearch bool, timestamp int64) (string, error) {
	ts := timestamp / 1000 // 秒级时间戳
	body := map[string]interface{}{
		"chat": map[string]interface{}{
			"id":     "",
			"title":  "新聊天",
			"models": []string{model},
			"params": map[string]interface{}{},
			"history": map[string]interface{}{
				"messages": map[string]interface{}{
					msgID: map[string]interface{}{
						"id":          msgID,
						"parentId":    nil,
						"childrenIds": []string{},
						"role":        "user",
						"content":     content,
						"timestamp":   ts,
						"models":      []string{model},
					},
				},
				"currentId": msgID,
			},
			"tags":             []string{},
			"flags":            []string{},
			"features":         []map[string]interface{}{{"type": "tool_selector", "server": "tool_selector_h", "status": "hidden"}},
			"mcp_servers":      []string{},
			"enable_thinking":  enableThinking,
			"auto_web_search":  autoWebSearch,
			"message_version":  1,
			"extra":            map[string]interface{}{},
			"timestamp":        timestamp,
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://chat.z.ai/api/v1/chats/new", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://chat.z.ai")
	req.Header.Set("Referer", "https://chat.z.ai/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := DoRequestWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create chat failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	LogDebug("[CreateChat] Created chat: %s", result.ID)
	return result.ID, nil
}

func makeUpstreamRequest(token string, messages []Message, model string, tools []Tool) (*http.Response, string, error) {
	payload, err := DecodeJWTPayload(token)
	if err != nil || payload == nil {
		return nil, "", fmt.Errorf("invalid token")
	}

	userID := payload.ID
	timestamp := time.Now().UnixMilli()
	requestID := uuid.New().String()
	userMsgID := uuid.New().String()

	targetModel := GetTargetModel(model)
	latestUserContent := extractLatestUserContent(messages)
	imageURLs := extractAllImageURLs(messages)

	// 上游不支持 system 角色，将系统提示词合并到第一条用户消息中
	messages = mergeSystemMessages(messages)

	enableThinking := IsThinkingModel(model)
	webSearch := IsSearchModel(model)      // 强制搜索：仅 -search / -deepsearch 模型开启
	autoWebSearch := true                  // 默认开启自动搜索
	enableDeepSearch := IsDeepSearchModel(model)

	// 创建会话：z.ai 要求 chat_id 必须先通过 /api/v1/chats/new 创建
	chatID, err := createChat(token, targetModel, userMsgID, latestUserContent, enableThinking, autoWebSearch, timestamp)
	if err != nil {
		LogWarn("Failed to create chat, using random ID: %v", err)
		chatID = uuid.New().String()
	}

	signature := GenerateSignature(userID, requestID, latestUserContent, timestamp)

	chatURL := fmt.Sprintf("https://chat.z.ai/c/%s", chatID)
	pathname := fmt.Sprintf("/c/%s", chatID)

	urlParams := fmt.Sprintf("https://chat.z.ai/api/v2/chat/completions?timestamp=%d&requestId=%s&user_id=%s&version=0.0.1&platform=web&token=%s", timestamp, requestID, userID, token)
	urlParams += "&user_agent=" + url_pkg.QueryEscape("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	urlParams += "&language=zh-CN"
	urlParams += "&languages=" + url_pkg.QueryEscape("zh-CN,zh")
	urlParams += "&timezone=" + url_pkg.QueryEscape("Asia/Shanghai")
	urlParams += "&cookie_enabled=true"
	urlParams += "&screen_width=1920&screen_height=1080&screen_resolution=1920x1080"
	urlParams += "&viewport_height=1080&viewport_width=1920&viewport_size=1920x1080"
	urlParams += "&color_depth=24&pixel_ratio=1"
	urlParams += "&current_url=" + url_pkg.QueryEscape(chatURL)
	urlParams += "&pathname=" + url_pkg.QueryEscape(pathname)
	urlParams += "&search=&hash="
	urlParams += "&host=chat.z.ai&hostname=chat.z.ai"
	urlParams += "&protocol=https%3A&referrer="
	urlParams += "&title=" + url_pkg.QueryEscape("Z.ai - Free AI Chatbot & Agent powered by GLM-5 & GLM-4.7")
	urlParams += "&timezone_offset=-480"
	urlParams += "&local_time=" + url_pkg.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	urlParams += "&utc_time=" + url_pkg.QueryEscape(time.Now().UTC().Format(time.RFC1123))
	urlParams += "&is_mobile=false&is_touch=false&max_touch_points=0"
	urlParams += "&browser_name=Chrome&os_name=Mac+OS"
	urlParams += fmt.Sprintf("&signature_timestamp=%d", timestamp)
	url := urlParams

	if targetModel == "glm-4.5v" || targetModel == "glm-4.6v" || targetModel == "glm-5v" {
		autoWebSearch = false
	}

	flags := []string{}

	var mcpServers []string
	if targetModel == "glm-4.6v" {
		mcpServers = []string{"vlm-image-search", "vlm-image-recognition", "vlm-image-processing"}
	}
	if enableDeepSearch {
		mcpServers = append(mcpServers, "advanced-search")
	}

	urlToFileID := make(map[string]string)
	var filesData []map[string]interface{}
	if len(imageURLs) > 0 {
		files, _ := UploadImages(token, imageURLs)
		for i, f := range files {
			if i < len(imageURLs) {
				urlToFileID[imageURLs[i]] = f.ID
			}
			filesData = append(filesData, map[string]interface{}{
				"type":            f.Type,
				"file":            f.File,
				"id":              f.ID,
				"url":             f.URL,
				"name":            f.Name,
				"status":          f.Status,
				"size":            f.Size,
				"error":           f.Error,
				"itemId":          f.ItemID,
				"media":           f.Media,
				"ref_user_msg_id": userMsgID,
			})
		}
	}

	var upstreamMessages []map[string]interface{}
	for _, msg := range messages {
		upstreamMsg := msg.ToUpstreamMessage(urlToFileID)
		// tool 角色消息转换为 assistant 消息（上游不支持 tool role）
		if msg.Role == "tool" {
			upstreamMsg["role"] = "assistant"
		}
		upstreamMessages = append(upstreamMessages, upstreamMsg)
	}

	now := time.Now()
	body := map[string]interface{}{
		"stream":           true,
		"model":            targetModel,
		"messages":         upstreamMessages,
		"signature_prompt": latestUserContent,
		"params":           map[string]interface{}{},
		"extra":            map[string]interface{}{},
		"features": map[string]interface{}{
			"image_generation": false,
			"web_search":       webSearch,
			"auto_web_search":  autoWebSearch,
			"preview_mode":     enableThinking,
			"flags":            flags,
		},
		"variables": map[string]interface{}{
			"{{USER_NAME}}":         payload.Email,
			"{{USER_LOCATION}}":     "Unknown",
			"{{CURRENT_DATETIME}}":  now.Format("2006-01-02 15:04:05"),
			"{{CURRENT_DATE}}":      now.Format("2006-01-02"),
			"{{CURRENT_TIME}}":      now.Format("15:04:05"),
			"{{CURRENT_WEEKDAY}}":   now.Weekday().String(),
			"{{CURRENT_TIMEZONE}}":  "Asia/Shanghai",
			"{{USER_LANGUAGE}}":     "zh-CN",
		},
		"chat_id":                      chatID,
		"id":                           uuid.New().String(),
		"current_user_message_id":      userMsgID,
		"current_user_message_parent_id": nil,
		"background_tasks": map[string]interface{}{
			"title_generation": true,
			"tags_generation":  true,
		},
	}

	if len(mcpServers) > 0 {
		body["mcp_servers"] = mcpServers
	}

	if len(filesData) > 0 {
		body["files"] = filesData
	}

	// 注意：z.ai 不支持 OpenAI 格式的 tools 字段，发送会导致空响应
	// 客户端传入的 tools 仅用于接口兼容，不转发给上游

	bodyBytes, _ := json.Marshal(body)

	LogDebug("[Upstream] Request URL: %s", url)
	LogDebug("[Upstream] Request body: %s", string(bodyBytes))

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-FE-Version", GetFeVersion())
	req.Header.Set("X-Signature", signature)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Origin", "https://chat.z.ai")
	req.Header.Set("Referer", fmt.Sprintf("https://chat.z.ai/c/%s", uuid.New().String()))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set("Cookie", "token="+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	resp, err := DoRequestWithRetry(req)
	if err != nil {
		return nil, "", err
	}

	LogDebug("[Upstream] Response status: %d", resp.StatusCode)
	for k, v := range resp.Header {
		LogDebug("[Upstream] Response header: %s: %s", k, v)
	}

	return resp, targetModel, nil
}

type UpstreamData struct {
	Type string `json:"type"`
	Data struct {
		DeltaContent string `json:"delta_content"`
		EditContent  string `json:"edit_content"`
		Phase        string `json:"phase"`
		Done         bool   `json:"done"`
	} `json:"data"`
}

func (u *UpstreamData) GetEditContent() string {
	editContent := u.Data.EditContent
	if editContent == "" {
		return ""
	}

	if len(editContent) > 0 && editContent[0] == '"' {
		var unescaped string
		if err := json.Unmarshal([]byte(editContent), &unescaped); err == nil {
			LogDebug("[GetEditContent] Unescaped edit_content from JSON string")
			return unescaped
		}
	}

	return editContent
}

type ThinkingFilter struct {
	hasSeenFirstThinking bool
	buffer               string
	lastOutputChunk      string
	lastPhase            string
	thinkingRoundCount   int
}

func (f *ThinkingFilter) ProcessThinking(deltaContent string) string {
	if !f.hasSeenFirstThinking {
		f.hasSeenFirstThinking = true
		// 兼容新旧格式：新格式直接返回纯文本，旧格式用 "> " 引用包裹
		if idx := strings.Index(deltaContent, "> "); idx != -1 {
			deltaContent = deltaContent[idx+2:]
		}
		// 不再因为没有 "> " 前缀就丢弃内容
	}

	content := f.buffer + deltaContent
	f.buffer = ""

	// 兼容旧格式：去除 markdown 引用前缀
	content = strings.ReplaceAll(content, "\n> ", "\n")

	if strings.HasSuffix(content, "\n>") {
		f.buffer = "\n>"
		return content[:len(content)-2]
	}
	if strings.HasSuffix(content, "\n") {
		f.buffer = "\n"
		return content[:len(content)-1]
	}

	return content
}

func (f *ThinkingFilter) Flush() string {
	result := f.buffer
	f.buffer = ""
	return result
}

func (f *ThinkingFilter) ExtractCompleteThinking(editContent string) string {
	startIdx := strings.Index(editContent, "> ")
	if startIdx == -1 {
		return ""
	}
	startIdx += 2

	endIdx := strings.Index(editContent, "\n</details>")
	if endIdx == -1 {
		return ""
	}

	content := editContent[startIdx:endIdx]
	content = strings.ReplaceAll(content, "\n> ", "\n")
	return content
}

func (f *ThinkingFilter) ExtractIncrementalThinking(editContent string) string {
	completeThinking := f.ExtractCompleteThinking(editContent)
	if completeThinking == "" {
		return ""
	}

	if f.lastOutputChunk == "" {
		return completeThinking
	}

	idx := strings.Index(completeThinking, f.lastOutputChunk)
	if idx == -1 {
		return completeThinking
	}

	incrementalPart := completeThinking[idx+len(f.lastOutputChunk):]
	return incrementalPart
}

func (f *ThinkingFilter) ResetForNewRound() {
	f.lastOutputChunk = ""
	f.hasSeenFirstThinking = false
}

func HandleChatCompletions(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if token == "free" {
		anonymousToken, err := GetAnonymousToken()
		if err != nil {
			LogError("Failed to get anonymous token: %v", err)
			http.Error(w, "Failed to get anonymous token", http.StatusInternalServerError)
			return
		}
		token = anonymousToken
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Model == "" {
		req.Model = "GLM-5"
	}

	resp, modelName, err := makeUpstreamRequest(token, req.Messages, req.Model, req.Tools)
	if err != nil {
		LogError("Upstream request failed: %v", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		LogError("[OpenAI] Upstream error: status=%d, body=%s", resp.StatusCode, string(body))
		http.Error(w, "Upstream error", resp.StatusCode)
		return
	}

	completionID := fmt.Sprintf("chatcmpl-%s", uuid.New().String()[:29])

	if req.Stream {
		handleStreamResponse(w, resp.Body, completionID, modelName)
	} else {
		handleNonStreamResponse(w, resp.Body, completionID, modelName)
	}
}

func handleStreamResponse(w http.ResponseWriter, body io.ReadCloser, completionID, modelName string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	hasContent := false
	searchRefFilter := NewSearchRefFilter()
	thinkingFilter := &ThinkingFilter{}
	pendingSourcesMarkdown := ""
	pendingImageSearchMarkdown := ""
	totalContentOutputLength := 0 // 记录已输出的 content 字符长度

	for scanner.Scan() {
		line := scanner.Text()
		LogDebug("[Upstream] %s", line)

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}

		var upstream UpstreamData
		if err := json.Unmarshal([]byte(payload), &upstream); err != nil {
			continue
		}

		if upstream.Data.Phase == "done" {
			break
		}

		if upstream.Data.Phase == "thinking" && upstream.Data.DeltaContent != "" {
			isNewThinkingRound := false
			if thinkingFilter.lastPhase != "" && thinkingFilter.lastPhase != "thinking" {
				thinkingFilter.ResetForNewRound()
				thinkingFilter.thinkingRoundCount++
				isNewThinkingRound = true
			}
			thinkingFilter.lastPhase = "thinking"

			reasoningContent := thinkingFilter.ProcessThinking(upstream.Data.DeltaContent)

			if isNewThinkingRound && thinkingFilter.thinkingRoundCount > 1 && reasoningContent != "" {
				reasoningContent = "\n\n" + reasoningContent
			}

			if reasoningContent != "" {
				thinkingFilter.lastOutputChunk = reasoningContent
				reasoningContent = searchRefFilter.Process(reasoningContent)

				if reasoningContent != "" {
					hasContent = true
					chunk := ChatCompletionChunk{
						ID:      completionID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   modelName,
						Choices: []Choice{{
							Index:        0,
							Delta:        Delta{ReasoningContent: reasoningContent},
							FinishReason: nil,
						}},
					}
					data, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				}
			}
			continue
		}

		if upstream.Data.Phase != "" {
			thinkingFilter.lastPhase = upstream.Data.Phase
		}

		editContent := upstream.GetEditContent()
		if editContent != "" && IsSearchResultContent(editContent) {
			if results := ParseSearchResults(editContent); len(results) > 0 {
				searchRefFilter.AddSearchResults(results)
				pendingSourcesMarkdown = searchRefFilter.GetSearchResultsMarkdown()
			}
			continue
		}
		if editContent != "" && strings.Contains(editContent, `"search_image"`) {
			textBeforeBlock := ExtractTextBeforeGlmBlock(editContent)
			if textBeforeBlock != "" {
				textBeforeBlock = searchRefFilter.Process(textBeforeBlock)
				if textBeforeBlock != "" {
					hasContent = true
					chunk := ChatCompletionChunk{
						ID:      completionID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   modelName,
						Choices: []Choice{{
							Index:        0,
							Delta:        Delta{Content: textBeforeBlock},
							FinishReason: nil,
						}},
					}
					data, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				}
			}
			if results := ParseImageSearchResults(editContent); len(results) > 0 {
				pendingImageSearchMarkdown = FormatImageSearchResults(results)
			}
			continue
		}
		if editContent != "" && strings.Contains(editContent, `"mcp"`) {
			textBeforeBlock := ExtractTextBeforeGlmBlock(editContent)
			if textBeforeBlock != "" {
				textBeforeBlock = searchRefFilter.Process(textBeforeBlock)
				if textBeforeBlock != "" {
					hasContent = true
					chunk := ChatCompletionChunk{
						ID:      completionID,
						Object:  "chat.completion.chunk",
						Created: time.Now().Unix(),
						Model:   modelName,
						Choices: []Choice{{
							Index:        0,
							Delta:        Delta{Content: textBeforeBlock},
							FinishReason: nil,
						}},
					}
					data, _ := json.Marshal(chunk)
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				}
			}
			continue
		}
		if editContent != "" && IsSearchToolCall(editContent, upstream.Data.Phase) {
			continue
		}

		if pendingSourcesMarkdown != "" {
			hasContent = true
			chunk := ChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []Choice{{
					Index:        0,
					Delta:        Delta{Content: pendingSourcesMarkdown},
					FinishReason: nil,
				}},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			pendingSourcesMarkdown = ""
		}
		if pendingImageSearchMarkdown != "" {
			hasContent = true
			chunk := ChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []Choice{{
					Index:        0,
					Delta:        Delta{Content: pendingImageSearchMarkdown},
					FinishReason: nil,
				}},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			pendingImageSearchMarkdown = ""
		}

		content := ""
		reasoningContent := ""

		if thinkingRemaining := thinkingFilter.Flush(); thinkingRemaining != "" {
			thinkingFilter.lastOutputChunk = thinkingRemaining
			processedRemaining := searchRefFilter.Process(thinkingRemaining)
			if processedRemaining != "" {
				hasContent = true
				chunk := ChatCompletionChunk{
					ID:      completionID,
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   modelName,
					Choices: []Choice{{
						Index:        0,
						Delta:        Delta{ReasoningContent: processedRemaining},
						FinishReason: nil,
					}},
				}
				data, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}

		if pendingSourcesMarkdown != "" && thinkingFilter.hasSeenFirstThinking {
			hasContent = true
			chunk := ChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []Choice{{
					Index:        0,
					Delta:        Delta{ReasoningContent: pendingSourcesMarkdown},
					FinishReason: nil,
				}},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			pendingSourcesMarkdown = ""
		}

		if upstream.Data.Phase == "answer" && upstream.Data.DeltaContent != "" {
			content = upstream.Data.DeltaContent
		} else if upstream.Data.Phase == "answer" && editContent != "" {
			if strings.Contains(editContent, "</details>") {
				reasoningContent = thinkingFilter.ExtractIncrementalThinking(editContent)

				if idx := strings.Index(editContent, "</details>"); idx != -1 {
					afterDetails := editContent[idx+len("</details>"):]
					if strings.HasPrefix(afterDetails, "\n") {
						content = afterDetails[1:]
					} else {
						content = afterDetails
					}
					totalContentOutputLength = len([]rune(content))
				}
			}
		} else if (upstream.Data.Phase == "other" || upstream.Data.Phase == "tool_call") && editContent != "" {
			fullContent := editContent
			fullContentRunes := []rune(fullContent)

			if len(fullContentRunes) > totalContentOutputLength {
				content = string(fullContentRunes[totalContentOutputLength:])
				totalContentOutputLength = len(fullContentRunes)
			} else {
				content = fullContent
			}
		}

		if reasoningContent != "" {
			reasoningContent = searchRefFilter.Process(reasoningContent) + searchRefFilter.Flush()
		}
		if reasoningContent != "" {
			hasContent = true
			chunk := ChatCompletionChunk{
				ID:      completionID,
				Object:  "chat.completion.chunk",
				Created: time.Now().Unix(),
				Model:   modelName,
				Choices: []Choice{{
					Index:        0,
					Delta:        Delta{ReasoningContent: reasoningContent},
					FinishReason: nil,
				}},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		if content == "" {
			continue
		}

		content = searchRefFilter.Process(content)
		if content == "" {
			continue
		}

		hasContent = true
		if upstream.Data.Phase == "answer" && upstream.Data.DeltaContent != "" {
			totalContentOutputLength += len([]rune(content))
		}

		chunk := ChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   modelName,
			Choices: []Choice{{
				Index:        0,
				Delta:        Delta{Content: content},
				FinishReason: nil,
			}},
		}

		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		LogError("[Upstream] scanner error: %v", err)
	}

	if remaining := searchRefFilter.Flush(); remaining != "" {
		hasContent = true
		chunk := ChatCompletionChunk{
			ID:      completionID,
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   modelName,
			Choices: []Choice{{
				Index:        0,
				Delta:        Delta{Content: remaining},
				FinishReason: nil,
			}},
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	if !hasContent {
		LogError("Stream response 200 but no content received")
	}

	stopReason := "stop"
	finalChunk := ChatCompletionChunk{
		ID:      completionID,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   modelName,
		Choices: []Choice{{
			Index:        0,
			Delta:        Delta{},
			FinishReason: &stopReason,
		}},
	}

	data, _ := json.Marshal(finalChunk)
	fmt.Fprintf(w, "data: %s\n\n", data)
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func handleNonStreamResponse(w http.ResponseWriter, body io.ReadCloser, completionID, modelName string) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var chunks []string
	var reasoningChunks []string
	thinkingFilter := &ThinkingFilter{}
	searchRefFilter := NewSearchRefFilter()
	hasThinking := false
	pendingSourcesMarkdown := ""
	pendingImageSearchMarkdown := ""

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}

		var upstream UpstreamData
		if err := json.Unmarshal([]byte(payload), &upstream); err != nil {
			continue
		}

		if upstream.Data.Phase == "done" {
			break
		}

		if upstream.Data.Phase == "thinking" && upstream.Data.DeltaContent != "" {
			if thinkingFilter.lastPhase != "" && thinkingFilter.lastPhase != "thinking" {
				thinkingFilter.ResetForNewRound()
				thinkingFilter.thinkingRoundCount++
				if thinkingFilter.thinkingRoundCount > 1 {
					reasoningChunks = append(reasoningChunks, "\n\n")
				}
			}
			thinkingFilter.lastPhase = "thinking"

			hasThinking = true
			reasoningContent := thinkingFilter.ProcessThinking(upstream.Data.DeltaContent)
			if reasoningContent != "" {
				thinkingFilter.lastOutputChunk = reasoningContent
				reasoningChunks = append(reasoningChunks, reasoningContent)
			}
			continue
		}

		if upstream.Data.Phase != "" {
			thinkingFilter.lastPhase = upstream.Data.Phase
		}

		editContent := upstream.GetEditContent()
		if editContent != "" && IsSearchResultContent(editContent) {
			if results := ParseSearchResults(editContent); len(results) > 0 {
				searchRefFilter.AddSearchResults(results)
				pendingSourcesMarkdown = searchRefFilter.GetSearchResultsMarkdown()
			}
			continue
		}
		if editContent != "" && strings.Contains(editContent, `"search_image"`) {
			textBeforeBlock := ExtractTextBeforeGlmBlock(editContent)
			if textBeforeBlock != "" {
				chunks = append(chunks, textBeforeBlock)
			}
			// 解析图片搜索结果
			if results := ParseImageSearchResults(editContent); len(results) > 0 {
				pendingImageSearchMarkdown = FormatImageSearchResults(results)
			}
			continue
		}
		if editContent != "" && strings.Contains(editContent, `"mcp"`) {
			textBeforeBlock := ExtractTextBeforeGlmBlock(editContent)
			if textBeforeBlock != "" {
				chunks = append(chunks, textBeforeBlock)
			}
			continue
		}
		if editContent != "" && IsSearchToolCall(editContent, upstream.Data.Phase) {
			continue
		}

		if pendingSourcesMarkdown != "" {
			if hasThinking {
				reasoningChunks = append(reasoningChunks, pendingSourcesMarkdown)
			} else {
				chunks = append(chunks, pendingSourcesMarkdown)
			}
			pendingSourcesMarkdown = ""
		}
		if pendingImageSearchMarkdown != "" {
			chunks = append(chunks, pendingImageSearchMarkdown)
			pendingImageSearchMarkdown = ""
		}

		content := ""
		if upstream.Data.Phase == "answer" && upstream.Data.DeltaContent != "" {
			content = upstream.Data.DeltaContent
		} else if upstream.Data.Phase == "answer" && editContent != "" {
			if strings.Contains(editContent, "</details>") {
				reasoningContent := thinkingFilter.ExtractIncrementalThinking(editContent)
				if reasoningContent != "" {
					reasoningChunks = append(reasoningChunks, reasoningContent)
				}

				if idx := strings.Index(editContent, "</details>"); idx != -1 {
					afterDetails := editContent[idx+len("</details>"):]
					if strings.HasPrefix(afterDetails, "\n") {
						content = afterDetails[1:]
					} else {
						content = afterDetails
					}
				}
			}
		} else if (upstream.Data.Phase == "other" || upstream.Data.Phase == "tool_call") && editContent != "" {
			content = editContent
		}

		if content != "" {
			chunks = append(chunks, content)
		}
	}

	fullContent := strings.Join(chunks, "")
	fullContent = searchRefFilter.Process(fullContent) + searchRefFilter.Flush()
	fullReasoning := strings.Join(reasoningChunks, "")
	fullReasoning = searchRefFilter.Process(fullReasoning) + searchRefFilter.Flush()

	if fullContent == "" {
		LogError("Non-stream response 200 but no content received")
	}

	stopReason := "stop"
	response := ChatCompletionResponse{
		ID:      completionID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   modelName,
		Choices: []Choice{{
			Index: 0,
			Message: &MessageResp{
				Role:             "assistant",
				Content:          fullContent,
				ReasoningContent: fullReasoning,
			},
			FinishReason: &stopReason,
		}},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func HandleModels(w http.ResponseWriter, r *http.Request) {
	var models []ModelInfo
	for _, id := range ModelList {
		// 解析模型能力
		_, hasThinking, hasSearch, _ := ParseModelName(id)

		models = append(models, ModelInfo{
			ID:      id,
			Object:  "model",
			OwnedBy: "z.ai",
			Capabilities: Capabilities{
				Vision:   true, // 所有模型都支持视觉
				Search:   hasSearch,
				Thinking: hasThinking,
			},
		})
	}

	response := ModelsResponse{
		Object: "list",
		Data:   models,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
