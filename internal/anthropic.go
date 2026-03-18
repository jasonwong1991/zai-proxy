package internal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// convertAnthropicToInternal converts an Anthropic Messages API request into the internal ChatRequest format.
// When tools are present, tool definitions are injected as an XML system prompt,
// and tool_use/tool_result blocks are converted to XML text format.
func convertAnthropicToInternal(req *AnthropicRequest) (*ChatRequest, error) {
	hasTools := len(req.Tools) > 0

	// Build tool_use_id → {name, arguments} map for tool_result conversion
	toolUseMap := make(map[string]map[string]string)
	if hasTools {
		for _, msg := range req.Messages {
			if blocks, ok := msg.Content.([]interface{}); ok {
				for _, item := range blocks {
					block, ok := item.(map[string]interface{})
					if !ok {
						continue
					}
					if blockType, _ := block["type"].(string); blockType == "tool_use" {
						id, _ := block["id"].(string)
						name, _ := block["name"].(string)
						argsJSON := "{}"
						if input := block["input"]; input != nil {
							if b, err := json.Marshal(input); err == nil {
								argsJSON = string(b)
							}
						}
						if id != "" {
							toolUseMap[id] = map[string]string{"name": name, "arguments": argsJSON}
						}
					}
				}
			}
		}
	}

	var messages []Message

	// Build system prompt (original system + tool definitions)
	systemText := ""
	if req.System != nil {
		switch s := req.System.(type) {
		case string:
			systemText = s
		case []interface{}:
			for _, item := range s {
				if block, ok := item.(map[string]interface{}); ok {
					if t, ok := block["type"].(string); ok && t == "text" {
						if text, ok := block["text"].(string); ok {
							systemText += text
						}
					}
				}
			}
		}
	}

	// Inject tool definitions into system prompt
	if hasTools {
		toolPrompt := FormatToolsSystemPrompt(req.Tools)
		if systemText != "" {
			systemText = toolPrompt + "\n\n" + systemText
		} else {
			systemText = toolPrompt
		}
	}

	if systemText != "" {
		messages = append(messages, Message{
			Role:    "system",
			Content: systemText,
		})
	}

	// Convert messages
	for _, msg := range req.Messages {
		converted := convertAnthropicMessageWithTools(msg, hasTools, toolUseMap)
		messages = append(messages, converted...)
	}

	// Determine model name
	model := req.Model
	if req.Thinking != nil && req.Thinking.Type == "enabled" {
		if !strings.HasSuffix(model, "-thinking") {
			model = model + "-thinking"
		}
	}

	// Tools are NOT forwarded to upstream (z.ai doesn't support them).
	// They are injected as XML system prompt instead.
	return &ChatRequest{
		Model:    model,
		Messages: messages,
		Stream:   req.Stream,
	}, nil
}

// convertAnthropicMessageWithTools converts an Anthropic message, handling tool_use/tool_result
// blocks by converting them to XML text format when tools are present.
func convertAnthropicMessageWithTools(msg AnthropicMessage, hasTools bool, toolUseMap map[string]map[string]string) []Message {
	switch content := msg.Content.(type) {
	case string:
		return []Message{{Role: msg.Role, Content: content}}
	case []interface{}:
		var textParts []string
		var imageParts []interface{}
		var toolUseCalls []map[string]interface{}
		hasImages := false

		for _, item := range content {
			block, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				text, _ := block["text"].(string)
				textParts = append(textParts, text)
			case "image":
				source, _ := block["source"].(map[string]interface{})
				if source == nil {
					continue
				}
				sourceType, _ := source["type"].(string)
				if sourceType == "base64" {
					mediaType, _ := source["media_type"].(string)
					data, _ := source["data"].(string)
					dataURI := fmt.Sprintf("data:%s;base64,%s", mediaType, data)
					imageParts = append(imageParts, map[string]interface{}{
						"type": "image_url",
						"image_url": map[string]interface{}{
							"url": dataURI,
						},
					})
					hasImages = true
				} else if sourceType == "url" {
					url, _ := source["url"].(string)
					imageParts = append(imageParts, map[string]interface{}{
						"type": "image_url",
						"image_url": map[string]interface{}{
							"url": url,
						},
					})
					hasImages = true
				}
			case "tool_use":
				if hasTools {
					name, _ := block["name"].(string)
				argsJSON := "{}"
				if input := block["input"]; input != nil {
					if b, err := json.Marshal(input); err == nil {
						argsJSON = string(b)
					}
				}
				toolUseCalls = append(toolUseCalls, map[string]interface{}{
					"name":      name,
					"arguments": argsJSON,
				})
				}
			case "tool_result":
				if hasTools {
					toolUseID, _ := block["tool_use_id"].(string)
					toolContent := extractToolResultContent(block)
					toolName := ""
					toolArgs := "{}"
					if info, ok := toolUseMap[toolUseID]; ok {
						toolName = info["name"]
						toolArgs = info["arguments"]
					}
					textParts = append(textParts, FormatToolResultXML(toolName, toolArgs, toolContent))
				} else {
					toolContent := extractToolResultContent(block)
					return []Message{{Role: "tool", Content: toolContent}}
				}
			}
		}

		// Format collected tool_use blocks as Toolify-style XML
		if len(toolUseCalls) > 0 {
			xml := FormatAssistantToolCallsXML(toolUseCalls)
			if xml != "" {
				textParts = append(textParts, xml)
			}
		}

		combinedText := strings.Join(textParts, "")

		if hasImages {
			var parts []interface{}
			if combinedText != "" {
				parts = append(parts, map[string]interface{}{
					"type": "text",
					"text": combinedText,
				})
			}
			parts = append(parts, imageParts...)
			if len(parts) > 0 {
				return []Message{{Role: msg.Role, Content: parts}}
			}
		}

		if combinedText != "" {
			return []Message{{Role: msg.Role, Content: combinedText}}
		}
		return []Message{{Role: msg.Role, Content: ""}}
	default:
		return []Message{{Role: msg.Role, Content: ""}}
	}
}

func extractToolResultContent(block map[string]interface{}) string {
	if c, ok := block["content"].(string); ok {
		return c
	}
	if blocks, ok := block["content"].([]interface{}); ok {
		var parts []string
		for _, b := range blocks {
			if tb, ok := b.(map[string]interface{}); ok {
				if t, ok := tb["type"].(string); ok && t == "text" {
					if text, ok := tb["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "")
	}
	return ""
}

func HandleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Also check x-api-key header (Anthropic SDK uses this)
	if token == "" {
		token = r.Header.Get("x-api-key")
	}
	if token == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    "authentication_error",
				"message": "Missing API key",
			},
		})
		return
	}

	if token == "free" {
		anonymousToken, err := GetAnonymousToken()
		if err != nil {
			LogError("Failed to get anonymous token: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "error",
				"error": map[string]interface{}{
					"type":    "api_error",
					"message": "Failed to get anonymous token",
				},
			})
			return
		}
		token = anonymousToken
	}

	var req AnthropicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    "invalid_request_error",
				"message": "Invalid request body",
			},
		})
		return
	}

	if req.Model == "" {
		req.Model = "GLM-5"
	}

	chatReq, err := convertAnthropicToInternal(&req)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    "invalid_request_error",
				"message": err.Error(),
			},
		})
		return
	}

	hasTools := len(req.Tools) > 0
	LogInfo("[Anthropic] model=%s, hasTools=%v, toolCount=%d, stream=%v",
		chatReq.Model, hasTools, len(req.Tools), req.Stream)

	resp, modelName, err := makeUpstreamRequest(token, chatReq.Messages, chatReq.Model, nil)
	if err != nil {
		LogError("Upstream request failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    "api_error",
				"message": "Upstream error",
			},
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		LogError("[Anthropic] Upstream error: status=%d, body=%s", resp.StatusCode, string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]interface{}{
				"type":    "api_error",
				"message": "Upstream error",
			},
		})
		return
	}

	messageID := fmt.Sprintf("msg_%s", uuid.New().String()[:29])

	if req.Stream {
		handleAnthropicStreamResponse(w, resp.Body, messageID, modelName, hasTools)
	} else {
		handleAnthropicNonStreamResponse(w, resp.Body, messageID, modelName, hasTools)
	}
}

func handleAnthropicNonStreamResponse(w http.ResponseWriter, body io.ReadCloser, messageID, modelName string, hasTools bool) {
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

	// Extract tool calls from content if tools were requested
	var parsedToolCalls []ParsedToolCall
	if hasTools {
		parsedToolCalls = ParseFunctionCallsXML(fullContent)
		LogDebug("[Anthropic-NonStream] Parsed %d tool calls from content (len=%d)", len(parsedToolCalls), len(fullContent))
		if pos := FindTriggerSignalPosition(fullContent); pos >= 0 {
			fullContent = strings.TrimSpace(fullContent[:pos])
		}
	}

	// Build content blocks
	var contentBlocks []ContentBlock
	if fullReasoning != "" {
		contentBlocks = append(contentBlocks, ContentBlock{
			Type:     "thinking",
			Thinking: fullReasoning,
		})
	}
	if fullContent != "" {
		contentBlocks = append(contentBlocks, ContentBlock{
			Type: "text",
			Text: fullContent,
		})
	}

	// Add tool_use content blocks
	for i, tc := range parsedToolCalls {
		toolID := fmt.Sprintf("toolu_%s_%d", uuid.New().String()[:8], i)
		var inputParsed interface{}
		if err := json.Unmarshal([]byte(tc.Arguments), &inputParsed); err != nil {
			inputParsed = map[string]interface{}{}
		}
		contentBlocks = append(contentBlocks, ContentBlock{
			Type:  "tool_use",
			ID:    toolID,
			Name:  tc.Name,
			Input: inputParsed,
		})
	}

	// If no content blocks at all, add empty text block
	if len(contentBlocks) == 0 {
		LogWarn("[Anthropic-NonStream] Response 200 but no content received")
		contentBlocks = append(contentBlocks, ContentBlock{
			Type: "text",
			Text: "",
		})
	}

	// Determine stop reason
	stopReason := "end_turn"
	if len(parsedToolCalls) > 0 {
		stopReason = "tool_use"
	}

	// Estimate token usage
	inputTokens := len(fullContent) / 4
	outputTokens := (len(fullContent) + len(fullReasoning)) / 4
	if inputTokens == 0 {
		inputTokens = 1
	}
	if outputTokens == 0 {
		outputTokens = 1
	}

	response := AnthropicResponse{
		ID:           messageID,
		Type:         "message",
		Role:         "assistant",
		Content:      contentBlocks,
		Model:        modelName,
		StopReason:   stopReason,
		StopSequence: nil,
		Usage: AnthropicUsage{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleAnthropicStreamResponse(w http.ResponseWriter, body io.ReadCloser, messageID, modelName string, hasTools bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Helper to write SSE events
	writeEvent := func(eventType string, data interface{}) {
		jsonData, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, jsonData)
		flusher.Flush()
	}

	// Send message_start
	writeEvent("message_start", map[string]interface{}{
		"type": "message_start",
		"message": map[string]interface{}{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"content":       []interface{}{},
			"model":         modelName,
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]interface{}{
				"input_tokens":  0,
				"output_tokens": 0,
			},
		},
	})

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	searchRefFilter := NewSearchRefFilter()
	thinkingFilter := &ThinkingFilter{}
	var toolContentBuffer []string // buffer text when hasTools for end-of-stream parsing
	pendingSourcesMarkdown := ""
	pendingImageSearchMarkdown := ""
	totalContentOutputLength := 0

	contentBlockIndex := 0
	thinkingBlockStarted := false
	textBlockStarted := false
	var allToolCalls []ParsedToolCall

	startThinkingBlock := func() {
		if !thinkingBlockStarted {
			writeEvent("content_block_start", map[string]interface{}{
				"type":  "content_block_start",
				"index": contentBlockIndex,
				"content_block": map[string]interface{}{
					"type":     "thinking",
					"thinking": "",
				},
			})
			thinkingBlockStarted = true
		}
	}

	stopThinkingBlock := func() {
		if thinkingBlockStarted {
			writeEvent("content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": contentBlockIndex,
			})
			contentBlockIndex++
			thinkingBlockStarted = false
		}
	}

	startTextBlock := func() {
		if !textBlockStarted {
			stopThinkingBlock()
			writeEvent("content_block_start", map[string]interface{}{
				"type":  "content_block_start",
				"index": contentBlockIndex,
				"content_block": map[string]interface{}{
					"type": "text",
					"text": "",
				},
			})
			textBlockStarted = true
		}
	}

	sendThinkingDelta := func(thinking string) {
		startThinkingBlock()
		writeEvent("content_block_delta", map[string]interface{}{
			"type":  "content_block_delta",
			"index": contentBlockIndex,
			"delta": map[string]interface{}{
				"type":     "thinking_delta",
				"thinking": thinking,
			},
		})
	}

	sendTextDelta := func(text string) {
		startTextBlock()
		writeEvent("content_block_delta", map[string]interface{}{
			"type":  "content_block_delta",
			"index": contentBlockIndex,
			"delta": map[string]interface{}{
				"type": "text_delta",
				"text": text,
			},
		})
	}

	outputTokens := 0

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

		// Thinking phase
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
					sendThinkingDelta(reasoningContent)
					outputTokens += len(reasoningContent) / 4
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
					sendTextDelta(textBeforeBlock)
					outputTokens += len(textBeforeBlock) / 4
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
					sendTextDelta(textBeforeBlock)
					outputTokens += len(textBeforeBlock) / 4
				}
			}
			continue
		}
		if editContent != "" && IsSearchToolCall(editContent, upstream.Data.Phase) {
			continue
		}

		if pendingSourcesMarkdown != "" {
			sendTextDelta(pendingSourcesMarkdown)
			outputTokens += len(pendingSourcesMarkdown) / 4
			pendingSourcesMarkdown = ""
		}
		if pendingImageSearchMarkdown != "" {
			sendTextDelta(pendingImageSearchMarkdown)
			outputTokens += len(pendingImageSearchMarkdown) / 4
			pendingImageSearchMarkdown = ""
		}

		// Flush thinking buffer
		if thinkingRemaining := thinkingFilter.Flush(); thinkingRemaining != "" {
			thinkingFilter.lastOutputChunk = thinkingRemaining
			processedRemaining := searchRefFilter.Process(thinkingRemaining)
			if processedRemaining != "" {
				sendThinkingDelta(processedRemaining)
				outputTokens += len(processedRemaining) / 4
			}
		}

		content := ""
		reasoningContent := ""

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
			if reasoningContent != "" {
				sendThinkingDelta(reasoningContent)
				outputTokens += len(reasoningContent) / 4
			}
		}

		if content == "" {
			continue
		}

		content = searchRefFilter.Process(content)
		if content == "" {
			continue
		}

		if upstream.Data.Phase == "answer" && upstream.Data.DeltaContent != "" {
			totalContentOutputLength += len([]rune(content))
		}

		// When tools are present, buffer content for end-of-stream parsing
		if hasTools {
			toolContentBuffer = append(toolContentBuffer, content)
		} else {
			sendTextDelta(content)
			outputTokens += len(content) / 4
		}
	}

	if err := scanner.Err(); err != nil {
		LogError("[Upstream] scanner error: %v", err)
	}

	// Flush remaining search ref buffer
	if remaining := searchRefFilter.Flush(); remaining != "" {
		if hasTools {
			toolContentBuffer = append(toolContentBuffer, remaining)
		} else {
			sendTextDelta(remaining)
			outputTokens += len(remaining) / 4
		}
	}

	// Parse buffered content for tool calls when tools are present
	if hasTools && len(toolContentBuffer) > 0 {
		bufferedContent := strings.Join(toolContentBuffer, "")

		allToolCalls = ParseFunctionCallsXML(bufferedContent)
		LogDebug("[Anthropic-Stream] Parsed %d tool calls from buffer (len=%d)", len(allToolCalls), len(bufferedContent))
		textContent := bufferedContent
		if pos := FindTriggerSignalPosition(bufferedContent); pos >= 0 {
			textContent = strings.TrimSpace(bufferedContent[:pos])
		}
		if textContent != "" {
			sendTextDelta(textContent)
			outputTokens += len(textContent) / 4
		}
	}

	// Close text block if open
	if textBlockStarted {
		writeEvent("content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": contentBlockIndex,
		})
		contentBlockIndex++
		textBlockStarted = false
	} else {
		stopThinkingBlock()
		if !thinkingBlockStarted {
			LogWarn("[Anthropic-Stream] Response 200 but no content received")
		}
	}

	// Emit tool_use content blocks
	for i, tc := range allToolCalls {
		toolID := fmt.Sprintf("toolu_%s_%d", uuid.New().String()[:8], i)

		// content_block_start for tool_use
		writeEvent("content_block_start", map[string]interface{}{
			"type":  "content_block_start",
			"index": contentBlockIndex,
			"content_block": map[string]interface{}{
				"type":  "tool_use",
				"id":    toolID,
				"name":  tc.Name,
				"input": map[string]interface{}{},
			},
		})

		// content_block_delta with input_json_delta
		writeEvent("content_block_delta", map[string]interface{}{
			"type":  "content_block_delta",
			"index": contentBlockIndex,
			"delta": map[string]interface{}{
				"type":         "input_json_delta",
				"partial_json": tc.Arguments,
			},
		})

		// content_block_stop
		writeEvent("content_block_stop", map[string]interface{}{
			"type":  "content_block_stop",
			"index": contentBlockIndex,
		})
		contentBlockIndex++
	}

	if outputTokens == 0 {
		outputTokens = 1
	}

	// Determine stop reason
	stopReason := "end_turn"
	if len(allToolCalls) > 0 {
		stopReason = "tool_use"
	}
	LogInfo("[Anthropic-Stream] stopReason=%s, toolCalls=%d", stopReason, len(allToolCalls))

	// Send message_delta with stop_reason
	writeEvent("message_delta", map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]interface{}{
			"output_tokens": outputTokens,
		},
	})

	// Send message_stop
	writeEvent("message_stop", map[string]interface{}{
		"type": "message_stop",
	})
}
