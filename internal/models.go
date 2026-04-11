package internal

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// 基础模型映射（不包含标签后缀）
var BaseModelMapping = map[string]string{
	"GLM-5":         "glm-5",
	"GLM-5.1":       "GLM-5.1",
	"GLM-5-Turbo":   "GLM-5-Turbo",
	"GLM-4.7":       "glm-4.7",
	"GLM-4.5":       "0727-360B-API",
	"GLM-4.6":       "GLM-4-6-API-V1",
	"GLM-4.5-V":     "glm-4.5v",
	"GLM-4.6-V":     "glm-4.6v",
	"GLM-5-V":       "glm-5v",
	"GLM-5V-Turbo":  "GLM-5V-Turbo",
	"GLM-4.5-Air":   "0727-106B-API",
	"0808-360B-DR":  "0808-360B-DR",
}

// v1/models 返回的模型列表（不包含所有标签组合）
var ModelList = []string{
	"GLM-5",
	"GLM-5-thinking",
	"GLM-5-search",
	"GLM-5-deepsearch",
	"GLM-5-thinking-search",
	"GLM-5-deepsearch-thinking",
	"GLM-5.1",
	"GLM-5.1-thinking",
	"GLM-5.1-search",
	"GLM-5.1-deepsearch",
	"GLM-5.1-thinking-search",
	"GLM-5.1-deepsearch-thinking",
	"GLM-5-Turbo",
	"GLM-5-Turbo-thinking",
	"GLM-5-Turbo-search",
	"GLM-5-Turbo-deepsearch",
	"GLM-5-Turbo-thinking-search",
	"GLM-5-Turbo-deepsearch-thinking",
	"GLM-4.7",
	"GLM-4.7-thinking",
	"GLM-4.7-search",
	"GLM-4.7-deepsearch",
	"GLM-4.7-thinking-search",
	"GLM-4.7-deepsearch-thinking",
	"GLM-4.5",
	"GLM-4.6",
	"GLM-4.5-thinking",
	"GLM-4.6-thinking",
	"GLM-4.5-V",
	"GLM-4.6-V",
	"GLM-5-V",
	"GLM-5V-Turbo",
	"GLM-4.6-V-thinking",
	"GLM-5-V-thinking",
	"GLM-5V-Turbo-thinking",
	"GLM-4.5-Air",
	"0808-360B-DR",
}

// 解析模型名称，提取基础模型名和标签
// 支持 -thinking、-search 和 -deepsearch 标签的任意排列组合
func ParseModelName(model string) (baseModel string, enableThinking bool, enableSearch bool, enableDeepSearch bool) {
	enableThinking = false
	enableSearch = false
	enableDeepSearch = false
	baseModel = model

	// 检查并移除 -thinking、-search 和 -deepsearch 标签（任意顺序）
	for {
		if strings.HasSuffix(baseModel, "-thinking") {
			enableThinking = true
			baseModel = strings.TrimSuffix(baseModel, "-thinking")
		} else if strings.HasSuffix(baseModel, "-deepsearch") {
			enableDeepSearch = true
			enableSearch = true // deepsearch 隐含 search
			baseModel = strings.TrimSuffix(baseModel, "-deepsearch")
		} else if strings.HasSuffix(baseModel, "-search") {
			enableSearch = true
			baseModel = strings.TrimSuffix(baseModel, "-search")
		} else {
			break
		}
	}

	return baseModel, enableThinking, enableSearch, enableDeepSearch
}

func IsThinkingModel(model string) bool {
	_, enableThinking, _, _ := ParseModelName(model)
	return enableThinking
}

func IsSearchModel(model string) bool {
	_, _, enableSearch, _ := ParseModelName(model)
	return enableSearch
}

func IsDeepSearchModel(model string) bool {
	_, _, _, enableDeepSearch := ParseModelName(model)
	return enableDeepSearch
}

func GetTargetModel(model string) string {
	baseModel, _, _, _ := ParseModelName(model)
	if target, ok := BaseModelMapping[baseModel]; ok {
		return target
	}
	return model
}

// OpenAI 格式的消息内容项
type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type ImageURL struct {
	URL string `json:"url"`
}

// Message 支持纯文本和多模态内容
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string 或 []ContentPart
}

// 解析消息内容，返回文本和图片URL列表
func (m *Message) ParseContent() (text string, imageURLs []string) {
	switch content := m.Content.(type) {
	case string:
		return content, nil
	case []interface{}:
		for _, item := range content {
			if part, ok := item.(map[string]interface{}); ok {
				partType, _ := part["type"].(string)
				if partType == "text" {
					if t, ok := part["text"].(string); ok {
						text += t
					}
				} else if partType == "image_url" {
					if imgURL, ok := part["image_url"].(map[string]interface{}); ok {
						if url, ok := imgURL["url"].(string); ok {
							imageURLs = append(imageURLs, url)
						}
					}
				}
			}
		}
	}
	return text, imageURLs
}

// 转换为上游消息格式，支持多模态
func (m *Message) ToUpstreamMessage(urlToFileID map[string]string) map[string]interface{} {
	text, imageURLs := m.ParseContent()

	// 无图片，返回纯文本
	if len(imageURLs) == 0 {
		return map[string]interface{}{
			"role":    m.Role,
			"content": text,
		}
	}

	// 有图片，构建多模态内容
	var content []interface{}
	if text != "" {
		content = append(content, map[string]interface{}{
			"type": "text",
			"text": text,
		})
	}
	for _, imgURL := range imageURLs {
		if fileID, ok := urlToFileID[imgURL]; ok {
			content = append(content, map[string]interface{}{
				"type": "image_url",
				"image_url": map[string]interface{}{
					"url": fileID,
				},
			})
		}
	}

	return map[string]interface{}{
		"role":    m.Role,
		"content": content,
	}
}

type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
	Tools    []Tool    `json:"tools,omitempty"`
}

// OpenAI 格式的工具定义
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Parameters  interface{} `json:"parameters,omitempty"`
}

// OpenAI 格式的工具调用（响应中）
type ToolCall struct {
	Index    int              `json:"index"`
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ChatCompletionChunk struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type Choice struct {
	Index        int          `json:"index"`
	Delta        Delta        `json:"delta,omitempty"`
	Message      *MessageResp `json:"message,omitempty"`
	FinishReason *string      `json:"finish_reason"`
}

type Delta struct {
	Role             string     `json:"role,omitempty"`
	Content          string     `json:"content,omitempty"`
	ReasoningContent string     `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
}

type MessageResp struct {
	Role             string     `json:"role"`
	Content          string     `json:"content"`
	ReasoningContent string     `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}

type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

type ModelInfo struct {
	ID           string       `json:"id"`
	Object       string       `json:"object"`
	OwnedBy      string       `json:"owned_by"`
	Capabilities Capabilities `json:"capabilities"`
}

type Capabilities struct {
	Vision   bool `json:"vision"`
	Search   bool `json:"search"`
	Thinking bool `json:"thinking"`
}

// Anthropic request types
type AnthropicRequest struct {
	Model         string             `json:"model"`
	MaxTokens     int                `json:"max_tokens"`
	Messages      []AnthropicMessage `json:"messages"`
	System        interface{}        `json:"system,omitempty"`
	Stream        bool               `json:"stream"`
	Temperature   *float64           `json:"temperature,omitempty"`
	Tools         []AnthropicTool    `json:"tools,omitempty"`
	Thinking      *ThinkingConfig    `json:"thinking,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
}

type AnthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type ContentBlock struct {
	Type      string      `json:"type"`
	Text      string      `json:"text,omitempty"`
	Source    *ImageSource `json:"source,omitempty"`
	ID        string      `json:"id,omitempty"`
	Name      string      `json:"name,omitempty"`
	Input     interface{} `json:"input,omitempty"`
	ToolUseID string      `json:"tool_use_id,omitempty"`
	Thinking  string      `json:"thinking,omitempty"`
}

type ImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
	URL       string `json:"url,omitempty"`
}

type AnthropicTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema interface{} `json:"input_schema"`
}

type ThinkingConfig struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens,omitempty"`
}

// Anthropic response types
type AnthropicResponse struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []ContentBlock `json:"content"`
	Model        string         `json:"model"`
	StopReason   string         `json:"stop_reason"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        AnthropicUsage `json:"usage"`
}

type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

var searchRefPattern = regexp.MustCompile(`【turn\d+search(\d+)】`)
var searchRefPrefixPattern = regexp.MustCompile(`【(t(u(r(n(\d+(s(e(a(r(c(h(\d+)?)?)?)?)?)?)?)?)?)?)?)?$`)

type SearchResult struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Index int    `json:"index"`
	RefID string `json:"ref_id"`
}

type SearchRefFilter struct {
	buffer        string
	searchResults map[string]SearchResult
}

func NewSearchRefFilter() *SearchRefFilter {
	return &SearchRefFilter{
		searchResults: make(map[string]SearchResult),
	}
}

func (f *SearchRefFilter) AddSearchResults(results []SearchResult) {
	for _, r := range results {
		f.searchResults[r.RefID] = r
	}
}

func escapeMarkdownTitle(title string) string {
	title = strings.ReplaceAll(title, `\`, `\\`)
	title = strings.ReplaceAll(title, `[`, `\[`)
	title = strings.ReplaceAll(title, `]`, `\]`)
	return title
}

func (f *SearchRefFilter) Process(content string) string {
	content = f.buffer + content
	f.buffer = ""

	if content == "" {
		return ""
	}

	content = searchRefPattern.ReplaceAllStringFunc(content, func(match string) string {
		runes := []rune(match)
		refID := string(runes[1 : len(runes)-1])
		if result, ok := f.searchResults[refID]; ok {
			return fmt.Sprintf(`[\[%d\]](%s)`, result.Index, result.URL)
		}
		return ""
	})

	if content == "" {
		return ""
	}

	maxPrefixLen := 20
	if len(content) < maxPrefixLen {
		maxPrefixLen = len(content)
	}

	for i := 1; i <= maxPrefixLen; i++ {
		suffix := content[len(content)-i:]
		if searchRefPrefixPattern.MatchString(suffix) {
			f.buffer = suffix
			return content[:len(content)-i]
		}
	}

	return content
}

func (f *SearchRefFilter) Flush() string {
	result := f.buffer
	f.buffer = ""
	if result != "" {
		result = searchRefPattern.ReplaceAllStringFunc(result, func(match string) string {
			runes := []rune(match)
			refID := string(runes[1 : len(runes)-1])
			if r, ok := f.searchResults[refID]; ok {
				return fmt.Sprintf(`[\[%d\]](%s)`, r.Index, r.URL)
			}
			return ""
		})
	}
	return result
}

func (f *SearchRefFilter) GetSearchResultsMarkdown() string {
	if len(f.searchResults) == 0 {
		return ""
	}

	var results []SearchResult
	for _, r := range f.searchResults {
		results = append(results, r)
	}
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Index > results[j].Index {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	var sb strings.Builder
	for _, r := range results {
		escapedTitle := escapeMarkdownTitle(r.Title)
		sb.WriteString(fmt.Sprintf("[\\[%d\\] %s](%s)\n", r.Index, escapedTitle, r.URL))
	}
	sb.WriteString("\n")
	return sb.String()
}

func IsSearchResultContent(editContent string) bool {
	return strings.Contains(editContent, `"search_result"`)
}

func ParseSearchResults(editContent string) []SearchResult {
	searchResultKey := `"search_result":`
	idx := strings.Index(editContent, searchResultKey)
	if idx == -1 {
		return nil
	}

	startIdx := idx + len(searchResultKey)
	for startIdx < len(editContent) && editContent[startIdx] != '[' {
		startIdx++
	}
	if startIdx >= len(editContent) {
		return nil
	}

	bracketCount := 0
	endIdx := startIdx
	for endIdx < len(editContent) {
		if editContent[endIdx] == '[' {
			bracketCount++
		} else if editContent[endIdx] == ']' {
			bracketCount--
			if bracketCount == 0 {
				endIdx++
				break
			}
		}
		endIdx++
	}

	if bracketCount != 0 {
		return nil
	}

	jsonStr := editContent[startIdx:endIdx]
	var rawResults []struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		Index int    `json:"index"`
		RefID string `json:"ref_id"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &rawResults); err != nil {
		return nil
	}

	var results []SearchResult
	for _, r := range rawResults {
		results = append(results, SearchResult{
			Title: r.Title,
			URL:   r.URL,
			Index: r.Index,
			RefID: r.RefID,
		})
	}

	return results
}

func IsSearchToolCall(editContent string, phase string) bool {
	if phase != "tool_call" {
		return false
	}
	// tool_call 阶段包含 mcp 相关内容的都跳过
	return strings.Contains(editContent, `"mcp"`) || strings.Contains(editContent, `mcp-server`)
}

type ImageSearchResult struct {
	Title     string `json:"title"`
	Link      string `json:"link"`
	Thumbnail string `json:"thumbnail"`
}

func ParseImageSearchResults(editContent string) []ImageSearchResult {
	resultKey := `"result":`
	idx := strings.Index(editContent, resultKey)
	if idx == -1 {
		return nil
	}

	startIdx := idx + len(resultKey)
	for startIdx < len(editContent) && editContent[startIdx] != '[' {
		startIdx++
	}
	if startIdx >= len(editContent) {
		return nil
	}

	bracketCount := 0
	endIdx := startIdx
	inString := false
	escapeNext := false
	for endIdx < len(editContent) {
		ch := editContent[endIdx]

		if escapeNext {
			escapeNext = false
			endIdx++
			continue
		}

		if ch == '\\' {
			escapeNext = true
			endIdx++
			continue
		}

		if ch == '"' {
			inString = !inString
		}

		if !inString {
			if ch == '[' || ch == '{' {
				bracketCount++
			} else if ch == ']' || ch == '}' {
				bracketCount--
				if bracketCount == 0 && ch == ']' {
					endIdx++
					break
				}
			}
		}
		endIdx++
	}

	if bracketCount != 0 {
		return nil
	}

	jsonStr := editContent[startIdx:endIdx]

	var rawResults []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &rawResults); err != nil {
		return nil
	}

	var results []ImageSearchResult
	for _, item := range rawResults {
		if itemType, ok := item["type"].(string); ok && itemType == "text" {
			if text, ok := item["text"].(string); ok {
				result := parseImageSearchText(text)
				if result.Title != "" && result.Link != "" {
					results = append(results, result)
				}
			}
		}
	}

	return results
}

func parseImageSearchText(text string) ImageSearchResult {
	result := ImageSearchResult{}

	if titleIdx := strings.Index(text, "Title: "); titleIdx != -1 {
		titleStart := titleIdx + len("Title: ")
		titleEnd := strings.Index(text[titleStart:], ";")
		if titleEnd != -1 {
			result.Title = strings.TrimSpace(text[titleStart : titleStart+titleEnd])
		}
	}

	if linkIdx := strings.Index(text, "Link: "); linkIdx != -1 {
		linkStart := linkIdx + len("Link: ")
		linkEnd := strings.Index(text[linkStart:], ";")
		if linkEnd != -1 {
			result.Link = strings.TrimSpace(text[linkStart : linkStart+linkEnd])
		} else {
			result.Link = strings.TrimSpace(text[linkStart:])
		}
	}

	if thumbnailIdx := strings.Index(text, "Thumbnail: "); thumbnailIdx != -1 {
		thumbnailStart := thumbnailIdx + len("Thumbnail: ")
		result.Thumbnail = strings.TrimSpace(text[thumbnailStart:])
	}

	return result
}

func FormatImageSearchResults(results []ImageSearchResult) string {
	if len(results) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, r := range results {
		escapedTitle := strings.ReplaceAll(r.Title, `[`, `\[`)
		escapedTitle = strings.ReplaceAll(escapedTitle, `]`, `\]`)
		sb.WriteString(fmt.Sprintf("\n![%s](%s)", escapedTitle, r.Link))
	}
	sb.WriteString("\n")
	return sb.String()
}

func ExtractTextBeforeGlmBlock(editContent string) string {
	if idx := strings.Index(editContent, "<glm_block"); idx != -1 {
		text := editContent[:idx]
		if strings.HasSuffix(text, "\n") {
			text = text[:len(text)-1]
		}
		return text
	}
	return ""
}

// ============================================================================
// Toolify-style XML Tool Calling (compatible with z.ai model training)
// ============================================================================

// ParsedToolCall represents a parsed function call from model output
type ParsedToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // raw JSON string
}

// TriggerSignal is a unique-per-instance signal the model outputs before function calls.
// Randomized to avoid collisions with normal text.
var TriggerSignal string

func init() {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 4)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	TriggerSignal = fmt.Sprintf("<Function_%s_Start/>", string(b))
}

// FormatToolsSystemPrompt generates the Toolify-style function calling prompt.
// Matches the format from openai.py that the z.ai model is trained on.
func FormatToolsSystemPrompt(tools []AnthropicTool) string {
	if len(tools) == 0 {
		return ""
	}

	var toolLines []string
	for i, t := range tools {
		desc := t.Description
		if desc == "" {
			desc = "None"
		}
		paramsJSON := "{}"
		if t.InputSchema != nil {
			if b, err := json.Marshal(t.InputSchema); err == nil {
				paramsJSON = string(b)
			}
		}
		// Extract required fields from schema
		required := "None"
		if schema, ok := t.InputSchema.(map[string]interface{}); ok {
			if reqList, ok := schema["required"].([]interface{}); ok && len(reqList) > 0 {
				var names []string
				for _, r := range reqList {
					if s, ok := r.(string); ok {
						names = append(names, s)
					}
				}
				if len(names) > 0 {
					required = strings.Join(names, ", ")
				}
			}
		}
		toolLines = append(toolLines, fmt.Sprintf(
			"%d. <tool name=\"%s\">\n   Description: %s\n   Required: %s\n   Parameters JSON Schema: %s",
			i+1, t.Name, desc, required, paramsJSON,
		))
	}

	toolsBlock := strings.Join(toolLines, "\n\n")

	return fmt.Sprintf(
		"CRITICAL: You have access to tools. When you need to call a tool, you MUST output the exact XML format below.\n\n"+
			"When you need to call tools, you MUST output exactly:\n"+
			"%s\n"+
			"<function_calls>\n"+
			"  <function_call>\n"+
			"    <name>tool_name</name>\n"+
			"    <args_json>{\"arg\":\"value\"}</args_json>\n"+
			"  </function_call>\n"+
			"</function_calls>\n\n"+
			"IMPORTANT Rules:\n"+
			"1) args_json MUST be valid JSON object\n"+
			"2) For multiple calls, output one <function_calls> with multiple <function_call> children\n"+
			"3) If no tool is needed, answer normally\n"+
			"4) DO NOT explain or describe the tool call - just output the XML format above\n"+
			"5) The trigger signal and XML tags are MANDATORY when calling tools\n\n"+
			"Available tools:\n%s\n\n"+
			"REMINDER: To call a tool, start with %s followed by <function_calls> XML.",
		TriggerSignal, toolsBlock, TriggerSignal,
	)
}

// FormatAssistantToolCallsXML converts tool_use blocks to the XML format the model expects.
func FormatAssistantToolCallsXML(toolCalls []map[string]interface{}) string {
	var blocks []string
	for _, tc := range toolCalls {
		name, _ := tc["name"].(string)
		if name == "" {
			continue
		}
		args := tc["arguments"]
		if args == nil {
			args = tc["input"] // fallback for raw Anthropic blocks
		}
		argsText := "{}"
		if s, ok := args.(string); ok {
			argsText = s
		} else if args != nil {
			if b, err := json.Marshal(args); err == nil {
				argsText = string(b)
			}
		}
		blocks = append(blocks, fmt.Sprintf(
			"<function_call>\n<name>%s</name>\n<args_json>%s</args_json>\n</function_call>",
			name, argsText,
		))
	}
	if len(blocks) == 0 {
		return ""
	}
	return fmt.Sprintf("%s\n<function_calls>\n%s\n</function_calls>",
		TriggerSignal, strings.Join(blocks, "\n"))
}

// FormatToolResultXML converts a tool result into XML format.
func FormatToolResultXML(toolName, toolArgs, resultContent string) string {
	return fmt.Sprintf(
		"<tool_execution_result>\n<tool_name>%s</tool_name>\n<tool_arguments>%s</tool_arguments>\n<tool_output>%s</tool_output>\n</tool_execution_result>",
		toolName, toolArgs, resultContent,
	)
}

// ParseFunctionCallsXML parses Toolify-style function calls from model output.
// Returns parsed tool calls (with generated IDs) or nil if none found.
func ParseFunctionCallsXML(text string) []ParsedToolCall {
	if !strings.Contains(text, TriggerSignal) {
		return nil
	}

	// Find the last occurrence of trigger signal
	pos := strings.LastIndex(text, TriggerSignal)
	if pos == -1 {
		return nil
	}
	sub := text[pos:]

	// Find <function_calls>...</function_calls>
	fcPattern := regexp.MustCompile(`<function_calls>([\s\S]*?)</function_calls>`)
	m := fcPattern.FindStringSubmatch(sub)
	if m == nil {
		return nil
	}

	callsBlock := m[1]
	callPattern := regexp.MustCompile(`<function_call>([\s\S]*?)</function_call>`)
	chunks := callPattern.FindAllStringSubmatch(callsBlock, -1)

	var out []ParsedToolCall
	for _, chunk := range chunks {
		namePattern := regexp.MustCompile(`<name>([\s\S]*?)</name>`)
		argsPattern := regexp.MustCompile(`<args_json>([\s\S]*?)</args_json>`)

		nameMatch := namePattern.FindStringSubmatch(chunk[1])
		argsMatch := argsPattern.FindStringSubmatch(chunk[1])
		if nameMatch == nil {
			continue
		}

		name := strings.TrimSpace(nameMatch[1])
		argsRaw := "{}"
		if argsMatch != nil {
			argsRaw = strings.TrimSpace(argsMatch[1])
		}

		// Validate JSON
		var parsed interface{}
		if err := json.Unmarshal([]byte(argsRaw), &parsed); err != nil {
			// Try to salvage
			argsRaw = fmt.Sprintf(`{"raw": %s}`, strconv.Quote(argsRaw))
		}

		out = append(out, ParsedToolCall{
			ID:        fmt.Sprintf("call_%s", uuid.New().String()[:24]),
			Name:      name,
			Arguments: argsRaw,
		})
	}

	return out
}

// FindTriggerSignalPosition returns the position of the last trigger signal in text,
// or -1 if not found. Used to split text into prefix (normal content) and tool calls.
func FindTriggerSignalPosition(text string) int {
	return strings.LastIndex(text, TriggerSignal)
}
