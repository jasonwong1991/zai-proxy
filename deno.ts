// deno.ts - z.ai to OpenAI API Proxy
// Run: deno run --allow-net --allow-env deno.ts

// ============================================================================
// Logger
// ============================================================================
type LogLevel = 0 | 1 | 2 | 3;
const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 } as const;
const LEVEL_NAMES = ["DEBUG", "INFO", "WARN", "ERROR"];
const LEVEL_COLORS = ["\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m"];
const RESET = "\x1b[0m";

let currentLogLevel: LogLevel = LOG_LEVELS.INFO;

function initLogger() {
  const level = Deno.env.get("LOG_LEVEL")?.toUpperCase();
  if (level === "DEBUG") currentLogLevel = LOG_LEVELS.DEBUG;
  else if (level === "WARN") currentLogLevel = LOG_LEVELS.WARN;
  else if (level === "ERROR") currentLogLevel = LOG_LEVELS.ERROR;
}

function log(level: LogLevel, format: string, ...args: unknown[]) {
  if (level < currentLogLevel) return;
  const now = new Date();
  const ts = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, "0")}/${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
  console.log(`${LEVEL_COLORS[level]}[${LEVEL_NAMES[level]}]${RESET} ${ts} ${format}`, ...args);
}

const logDebug = (f: string, ...a: unknown[]) => log(0, f, ...a);
const logInfo = (f: string, ...a: unknown[]) => log(1, f, ...a);
const logWarn = (f: string, ...a: unknown[]) => log(2, f, ...a);
const logError = (f: string, ...a: unknown[]) => log(3, f, ...a);

// ============================================================================
// Config
// ============================================================================
const PORT = parseInt(Deno.env.get("PORT") || "8000");

// ============================================================================
// Models
// ============================================================================
const BASE_MODEL_MAPPING: Record<string, string> = {
  "GLM-5": "glm-5",
  "GLM-4.7": "glm-4.7",
  "GLM-4.5": "0727-360B-API",
  "GLM-4.6": "GLM-4-6-API-V1",
  "GLM-4.5-V": "glm-4.5v",
  "GLM-4.6-V": "glm-4.6v",
  "GLM-5-V": "glm-5v",
  "GLM-4.5-Air": "0727-106B-API",
  "0808-360B-DR": "0808-360B-DR",
};

const MODEL_LIST = [
  "GLM-5", "GLM-5-thinking", "GLM-5-search", "GLM-5-deepsearch",
  "GLM-5-thinking-search", "GLM-5-deepsearch-thinking",
  "GLM-4.7", "GLM-4.7-thinking", "GLM-4.7-search", "GLM-4.7-deepsearch",
  "GLM-4.7-thinking-search", "GLM-4.7-deepsearch-thinking",
  "GLM-4.5", "GLM-4.6", "GLM-4.5-thinking", "GLM-4.6-thinking",
  "GLM-4.5-V", "GLM-4.6-V", "GLM-5-V", "GLM-4.6-V-thinking", "GLM-5-V-thinking", "GLM-4.5-Air", "0808-360B-DR",
];

function parseModelName(model: string) {
  let baseModel = model;
  let enableThinking = false;
  let enableSearch = false;
  let enableDeepSearch = false;
  while (true) {
    if (baseModel.endsWith("-thinking")) {
      enableThinking = true;
      baseModel = baseModel.slice(0, -9);
    } else if (baseModel.endsWith("-deepsearch")) {
      enableDeepSearch = true;
      enableSearch = true; // deepsearch 隐含 search
      baseModel = baseModel.slice(0, -11);
    } else if (baseModel.endsWith("-search")) {
      enableSearch = true;
      baseModel = baseModel.slice(0, -7);
    } else break;
  }
  return { baseModel, enableThinking, enableSearch, enableDeepSearch };
}

function getTargetModel(model: string): string {
  const { baseModel } = parseModelName(model);
  return BASE_MODEL_MAPPING[baseModel] || model;
}

// ============================================================================
// JWT Decoder
// ============================================================================
interface JWTPayload { id: string; email: string }

function decodeJWTPayload(token: string): JWTPayload | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  let payload = parts[1];
  const padding = 4 - (payload.length % 4);
  if (padding !== 4) payload += "=".repeat(padding);
  try {
    const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded);
  } catch {
    try {
      const decoded = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(decoded);
    } catch { return null; }
  }
}

// ============================================================================
// Signature Generator
// ============================================================================
async function hmacSha256Hex(key: string | Uint8Array, data: string): Promise<string> {
  const enc = new TextEncoder();
  const keyData = typeof key === "string" ? enc.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function generateSignature(userID: string, requestID: string, userContent: string, timestamp: number): Promise<string> {
  const requestInfo = `requestId,${requestID},timestamp,${timestamp},user_id,${userID}`;
  const contentBytes = new TextEncoder().encode(userContent);
  const contentBase64 = btoa(String.fromCharCode(...contentBytes));
  const signData = `${requestInfo}|${contentBase64}|${timestamp}`;
  const period = Math.floor(timestamp / (5 * 60 * 1000));
  const firstHmac = await hmacSha256Hex("key-@@@@)))()((9))-xxxx&&&%%%%%", String(period));
  return await hmacSha256Hex(firstHmac, signData);
}

// ============================================================================
// Version Updater
// ============================================================================
let feVersion = "";

async function fetchFeVersion() {
  try {
    const resp = await fetch("https://chat.z.ai/");
    if (!resp.ok) return;
    const body = await resp.text();
    const match = body.match(/prod-fe-[\.\d]+/);
    if (match) {
      feVersion = match[0];
      logInfo("Updated fe version: %s", feVersion);
    }
  } catch (e) { logError("Failed to fetch fe version: %s", e); }
}

function startVersionUpdater() {
  fetchFeVersion();
  setInterval(fetchFeVersion, 3600 * 1000);
}

// ============================================================================
// Anonymous Token
// ============================================================================
async function getAnonymousToken(): Promise<string> {
  const resp = await fetch("https://chat.z.ai/api/v1/auths/");
  if (!resp.ok) throw new Error(`status ${resp.status}`);
  const data = await resp.json();
  return data.token;
}

// ============================================================================
// Image Upload
// ============================================================================
interface FileUploadResponse {
  id: string;
  user_id: string;
  filename: string;
  meta: { name: string; content_type: string; size: number; cdn_url: string };
}

interface UpstreamFile {
  type: string;
  file: FileUploadResponse;
  id: string;
  url: string;
  name: string;
  status: string;
  size: number;
  error: string;
  itemId: string;
  media: string;
}

async function uploadImageFromURL(token: string, imageURL: string): Promise<UpstreamFile | null> {
  try {
    let imageData: Uint8Array;
    let filename: string;
    let contentType = "image/png";

    if (imageURL.startsWith("data:")) {
      const parts = imageURL.split(",");
      if (parts.length !== 2) return null;
      const header = parts[0];
      const mimeMatch = header.match(/data:([^;]+)/);
      if (mimeMatch) contentType = mimeMatch[1];
      imageData = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
      let ext = ".png";
      if (contentType.includes("jpeg") || contentType.includes("jpg")) ext = ".jpg";
      else if (contentType.includes("gif")) ext = ".gif";
      else if (contentType.includes("webp")) ext = ".webp";
      filename = crypto.randomUUID().slice(0, 12) + ext;
    } else {
      const resp = await fetch(imageURL);
      if (!resp.ok) return null;
      imageData = new Uint8Array(await resp.arrayBuffer());
      contentType = resp.headers.get("Content-Type") || "image/png";
      const urlPath = new URL(imageURL).pathname;
      filename = urlPath.split("/").pop() || "";
      if (!filename || filename === "." || filename === "/") {
        const ext = contentType.includes("jpeg") || contentType.includes("jpg") ? ".jpg" : ".png";
        filename = crypto.randomUUID().slice(0, 12) + ext;
      }
    }

    const formData = new FormData();
    formData.append("file", new Blob([imageData], { type: contentType }), filename);

    const resp = await fetch("https://chat.z.ai/api/v1/files/", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Origin": "https://chat.z.ai",
        "Referer": "https://chat.z.ai/",
      },
      body: formData,
    });

    if (!resp.ok) return null;
    const uploadResp: FileUploadResponse = await resp.json();

    return {
      type: "image",
      file: uploadResp,
      id: uploadResp.id,
      url: `/api/v1/files/${uploadResp.id}/content`,
      name: uploadResp.filename,
      status: "uploaded",
      size: uploadResp.meta.size,
      error: "",
      itemId: crypto.randomUUID(),
      media: "image",
    };
  } catch (e) {
    logError("Failed to upload image: %s", e);
    return null;
  }
}

async function uploadImages(token: string, imageURLs: string[]): Promise<UpstreamFile[]> {
  const files: UpstreamFile[] = [];
  for (const url of imageURLs) {
    const file = await uploadImageFromURL(token, url);
    if (file) files.push(file);
  }
  return files;
}

// ============================================================================
// Message Parsing
// ============================================================================
interface Message {
  role: string;
  content: string | ContentPart[];
}

interface ContentPart {
  type: string;
  text?: string;
  image_url?: { url: string };
}

function parseMessageContent(msg: Message): { text: string; imageURLs: string[] } {
  if (typeof msg.content === "string") return { text: msg.content, imageURLs: [] };
  let text = "";
  const imageURLs: string[] = [];
  for (const part of msg.content) {
    if (part.type === "text" && part.text) text += part.text;
    else if (part.type === "image_url" && part.image_url?.url) imageURLs.push(part.image_url.url);
  }
  return { text, imageURLs };
}

function toUpstreamMessage(msg: Message, urlToFileID: Record<string, string>): Record<string, unknown> {
  const { text, imageURLs } = parseMessageContent(msg);
  if (imageURLs.length === 0) return { role: msg.role, content: text };
  const content: unknown[] = [];
  if (text) content.push({ type: "text", text });
  for (const imgURL of imageURLs) {
    if (urlToFileID[imgURL]) {
      content.push({ type: "image_url", image_url: { url: urlToFileID[imgURL] } });
    }
  }
  return { role: msg.role, content };
}

// ============================================================================
// Search Reference Filter
// ============================================================================
interface SearchResult {
  title: string;
  url: string;
  index: number;
  ref_id: string;
}

const searchRefPattern = /【turn\d+search(\d+)】/g;
const searchRefPrefixPattern = /【(t(u(r(n(\d+(s(e(a(r(c(h(\d+)?)?)?)?)?)?)?)?)?)?)?)?$/;

class SearchRefFilter {
  private buffer = "";
  private searchResults = new Map<string, SearchResult>();

  addSearchResults(results: SearchResult[]) {
    for (const r of results) this.searchResults.set(r.ref_id, r);
  }

  process(content: string): string {
    content = this.buffer + content;
    this.buffer = "";
    if (!content) return "";

    content = content.replace(/【turn\d+search\d+】/g, (match) => {
      const refID = match.slice(1, -1);
      const r = this.searchResults.get(refID);
      if (r) return `[\\[${r.index}\\]](${r.url})`;
      return "";
    });

    if (!content) return "";
    const maxPrefixLen = Math.min(20, content.length);
    for (let i = 1; i <= maxPrefixLen; i++) {
      const suffix = content.slice(-i);
      if (searchRefPrefixPattern.test(suffix)) {
        this.buffer = suffix;
        return content.slice(0, -i);
      }
    }
    return content;
  }

  flush(): string {
    let result = this.buffer;
    this.buffer = "";
    if (result) {
      result = result.replace(/【turn\d+search\d+】/g, (match) => {
        const refID = match.slice(1, -1);
        const r = this.searchResults.get(refID);
        if (r) return `[\\[${r.index}\\]](${r.url})`;
        return "";
      });
    }
    return result;
  }

  getSearchResultsMarkdown(): string {
    if (this.searchResults.size === 0) return "";
    const results = Array.from(this.searchResults.values()).sort((a, b) => a.index - b.index);
    let sb = "";
    for (const r of results) {
      const escapedTitle = r.title.replace(/\\/g, "\\\\").replace(/\[/g, "\\[").replace(/\]/g, "\\]");
      sb += `[\\[${r.index}\\] ${escapedTitle}](${r.url})\n`;
    }
    return sb + "\n";
  }
}

function isSearchResultContent(editContent: string): boolean {
  return editContent.includes('"search_result"');
}

function parseSearchResults(editContent: string): SearchResult[] | null {
  const key = '"search_result":';
  const idx = editContent.indexOf(key);
  if (idx === -1) return null;
  let startIdx = idx + key.length;
  while (startIdx < editContent.length && editContent[startIdx] !== "[") startIdx++;
  if (startIdx >= editContent.length) return null;

  let bracketCount = 0, endIdx = startIdx;
  while (endIdx < editContent.length) {
    if (editContent[endIdx] === "[") bracketCount++;
    else if (editContent[endIdx] === "]") {
      bracketCount--;
      if (bracketCount === 0) { endIdx++; break; }
    }
    endIdx++;
  }
  if (bracketCount !== 0) return null;

  try {
    return JSON.parse(editContent.slice(startIdx, endIdx));
  } catch { return null; }
}

function isSearchToolCall(editContent: string, phase: string): boolean {
  if (phase !== "tool_call") return false;
  return editContent.includes('"mcp"') || editContent.includes("mcp-server");
}

// ============================================================================
// Image Search Results
// ============================================================================
interface ImageSearchResult {
  title: string;
  link: string;
  thumbnail: string;
}

function parseImageSearchResults(editContent: string): ImageSearchResult[] | null {
  const key = '"result":';
  const idx = editContent.indexOf(key);
  if (idx === -1) return null;
  let startIdx = idx + key.length;
  while (startIdx < editContent.length && editContent[startIdx] !== "[") startIdx++;
  if (startIdx >= editContent.length) return null;

  let bracketCount = 0, endIdx = startIdx, inString = false, escapeNext = false;
  while (endIdx < editContent.length) {
    const ch = editContent[endIdx];
    if (escapeNext) { escapeNext = false; endIdx++; continue; }
    if (ch === "\\") { escapeNext = true; endIdx++; continue; }
    if (ch === '"') inString = !inString;
    if (!inString) {
      if (ch === "[" || ch === "{") bracketCount++;
      else if (ch === "]" || ch === "}") {
        bracketCount--;
        if (bracketCount === 0 && ch === "]") { endIdx++; break; }
      }
    }
    endIdx++;
  }
  if (bracketCount !== 0) return null;

  try {
    const rawResults: { type?: string; text?: string }[] = JSON.parse(editContent.slice(startIdx, endIdx));
    const results: ImageSearchResult[] = [];
    for (const item of rawResults) {
      if (item.type === "text" && item.text) {
        const r = parseImageSearchText(item.text);
        if (r.title && r.link) results.push(r);
      }
    }
    return results;
  } catch { return null; }
}

function parseImageSearchText(text: string): ImageSearchResult {
  const result: ImageSearchResult = { title: "", link: "", thumbnail: "" };
  const titleIdx = text.indexOf("Title: ");
  if (titleIdx !== -1) {
    const start = titleIdx + 7;
    const end = text.indexOf(";", start);
    result.title = end !== -1 ? text.slice(start, end).trim() : text.slice(start).trim();
  }
  const linkIdx = text.indexOf("Link: ");
  if (linkIdx !== -1) {
    const start = linkIdx + 6;
    const end = text.indexOf(";", start);
    result.link = end !== -1 ? text.slice(start, end).trim() : text.slice(start).trim();
  }
  const thumbIdx = text.indexOf("Thumbnail: ");
  if (thumbIdx !== -1) result.thumbnail = text.slice(thumbIdx + 11).trim();
  return result;
}

function formatImageSearchResults(results: ImageSearchResult[]): string {
  if (results.length === 0) return "";
  let sb = "";
  for (const r of results) {
    const escapedTitle = r.title.replace(/\[/g, "\\[").replace(/\]/g, "\\]");
    sb += `\n![${escapedTitle}](${r.link})`;
  }
  return sb + "\n";
}

function extractTextBeforeGlmBlock(editContent: string): string {
  const idx = editContent.indexOf("<glm_block");
  if (idx !== -1) {
    let text = editContent.slice(0, idx);
    if (text.endsWith("\n")) text = text.slice(0, -1);
    return text;
  }
  return "";
}

// ============================================================================
// Toolify-style XML Tool Calling (compatible with z.ai model training)
// ============================================================================
interface ParsedToolCall {
  id: string;
  name: string;
  arguments: string; // raw JSON string
}

// Generate random trigger signal (unique per process start)
const TRIGGER_SIGNAL = (() => {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; i < 4; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return `<Function_${code}_Start/>`;
})();

function formatToolsSystemPrompt(tools: AnthropicTool[]): string {
  if (tools.length === 0) return "";
  const toolLines: string[] = [];
  for (let i = 0; i < tools.length; i++) {
    const t = tools[i];
    const desc = t.description || "None";
    const paramsJSON = t.input_schema ? JSON.stringify(t.input_schema) : "{}";
    let required = "None";
    if (t.input_schema && typeof t.input_schema === "object") {
      const schema = t.input_schema as Record<string, unknown>;
      if (Array.isArray(schema.required) && schema.required.length > 0) {
        required = schema.required.filter((r: unknown) => typeof r === "string").join(", ");
      }
    }
    toolLines.push(
      `${i + 1}. <tool name="${t.name}">\n` +
      `   Description: ${desc}\n` +
      `   Required: ${required}\n` +
      `   Parameters JSON Schema: ${paramsJSON}`
    );
  }
  const toolsBlock = toolLines.join("\n\n");
  return (
    "CRITICAL: You have access to tools. When you need to call a tool, you MUST output the exact XML format below.\n\n" +
    "When you need to call tools, you MUST output exactly:\n" +
    `${TRIGGER_SIGNAL}\n` +
    "<function_calls>\n" +
    "  <function_call>\n" +
    "    <name>tool_name</name>\n" +
    '    <args_json>{"arg":"value"}</args_json>\n' +
    "  </function_call>\n" +
    "</function_calls>\n\n" +
    "IMPORTANT Rules:\n" +
    "1) args_json MUST be valid JSON object\n" +
    "2) For multiple calls, output one <function_calls> with multiple <function_call> children\n" +
    "3) If no tool is needed, answer normally\n" +
    "4) DO NOT explain or describe the tool call - just output the XML format above\n" +
    "5) The trigger signal and XML tags are MANDATORY when calling tools\n\n" +
    "Available tools:\n" + toolsBlock + "\n\n" +
    `REMINDER: To call a tool, start with ${TRIGGER_SIGNAL} followed by <function_calls> XML.`
  );
}

function formatAssistantToolCallsXML(toolCalls: Record<string, unknown>[]): string {
  const blocks: string[] = [];
  for (const tc of toolCalls) {
    const name = tc.name as string;
    if (!name) continue;
    let argsText = "{}";
    if (typeof tc.arguments === "string") {
      argsText = tc.arguments;
    } else if (tc.arguments != null || tc.input != null) {
      argsText = JSON.stringify(tc.arguments ?? tc.input ?? {});
    }
    blocks.push(
      `<function_call>\n<name>${name}</name>\n<args_json>${argsText}</args_json>\n</function_call>`
    );
  }
  if (blocks.length === 0) return "";
  return `${TRIGGER_SIGNAL}\n<function_calls>\n${blocks.join("\n")}\n</function_calls>`;
}

function formatToolResultXML(toolName: string, toolArgs: string, resultContent: string): string {
  return (
    "<tool_execution_result>\n" +
    `<tool_name>${toolName}</tool_name>\n` +
    `<tool_arguments>${toolArgs}</tool_arguments>\n` +
    `<tool_output>${resultContent}</tool_output>\n` +
    "</tool_execution_result>"
  );
}

function parseFunctionCallsXML(text: string): ParsedToolCall[] {
  if (!text.includes(TRIGGER_SIGNAL)) {
    logDebug("[parseFunctionCallsXML] No trigger signal found in text (len=%d)", text.length);
    return [];
  }

  const pos = text.lastIndexOf(TRIGGER_SIGNAL);
  if (pos === -1) return [];
  const sub = text.slice(pos);
  logDebug("[parseFunctionCallsXML] Found trigger at pos=%d, sub length=%d", pos, sub.length);

  const fcMatch = sub.match(/<function_calls>([\s\S]*?)<\/function_calls>/);
  if (!fcMatch) {
    logWarn("[parseFunctionCallsXML] Trigger found but no <function_calls> block. Sub (first 300): %s", sub.slice(0, 300));
    return [];
  }

  const callsBlock = fcMatch[1];
  const callMatches = [...callsBlock.matchAll(/<function_call>([\s\S]*?)<\/function_call>/g)];
  logDebug("[parseFunctionCallsXML] Found %d <function_call> blocks", callMatches.length);

  const out: ParsedToolCall[] = [];
  for (const chunk of callMatches) {
    const nameMatch = chunk[1].match(/<name>([\s\S]*?)<\/name>/);
    const argsMatch = chunk[1].match(/<args_json>([\s\S]*?)<\/args_json>/);
    if (!nameMatch) continue;

    const name = nameMatch[1].trim();
    let argsRaw = argsMatch ? argsMatch[1].trim() : "{}";

    // Validate JSON
    try {
      JSON.parse(argsRaw);
    } catch {
      argsRaw = JSON.stringify({ raw: argsRaw });
    }

    out.push({
      id: `call_${crypto.randomUUID().slice(0, 24)}`,
      name,
      arguments: argsRaw,
    });
  }
  return out;
}

function findTriggerSignalPosition(text: string): number {
  return text.lastIndexOf(TRIGGER_SIGNAL);
}

// ============================================================================
// Thinking Filter
// ============================================================================
class ThinkingFilter {
  hasSeenFirstThinking = false;
  buffer = "";
  lastOutputChunk = "";
  lastPhase = "";
  thinkingRoundCount = 0;

  processThinking(deltaContent: string): string {
    if (!this.hasSeenFirstThinking) {
      this.hasSeenFirstThinking = true;
      const idx = deltaContent.indexOf("> ");
      if (idx !== -1) deltaContent = deltaContent.slice(idx + 2);
      else return "";
    }
    let content = this.buffer + deltaContent;
    this.buffer = "";
    content = content.replaceAll("\n> ", "\n");
    if (content.endsWith("\n>")) {
      this.buffer = "\n>";
      return content.slice(0, -2);
    }
    if (content.endsWith("\n")) {
      this.buffer = "\n";
      return content.slice(0, -1);
    }
    return content;
  }

  flush(): string {
    const result = this.buffer;
    this.buffer = "";
    return result;
  }

  extractCompleteThinking(editContent: string): string {
    const startIdx = editContent.indexOf("> ");
    if (startIdx === -1) return "";
    const endIdx = editContent.indexOf("\n</details>");
    if (endIdx === -1) return "";
    let content = editContent.slice(startIdx + 2, endIdx);
    content = content.replaceAll("\n> ", "\n");
    return content;
  }

  extractIncrementalThinking(editContent: string): string {
    const completeThinking = this.extractCompleteThinking(editContent);
    if (!completeThinking) return "";
    if (!this.lastOutputChunk) return completeThinking;
    const idx = completeThinking.indexOf(this.lastOutputChunk);
    if (idx === -1) return completeThinking;
    return completeThinking.slice(idx + this.lastOutputChunk.length);
  }

  resetForNewRound() {
    this.lastOutputChunk = "";
    this.hasSeenFirstThinking = false;
  }
}

// ============================================================================
// Upstream Data Types
// ============================================================================
interface UpstreamData {
  type: string;
  data: {
    delta_content: string;
    edit_content: string;
    phase: string;
    done: boolean;
  };
}

function getEditContent(upstream: UpstreamData): string {
  let editContent = upstream.data.edit_content;
  if (!editContent) return "";
  if (editContent.length > 0 && editContent[0] === '"') {
    try {
      const unescaped = JSON.parse(editContent);
      if (typeof unescaped === "string") return unescaped;
    } catch { /* ignore */ }
  }
  return editContent;
}

// ============================================================================
// Response Types
// ============================================================================
interface ChatCompletionChunk {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ChunkChoice[];
}

interface ChunkChoice {
  index: number;
  delta: { content?: string; reasoning_content?: string };
  finish_reason: string | null;
}

interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: ResponseChoice[];
}

interface ResponseChoice {
  index: number;
  message: { role: string; content: string; reasoning_content?: string };
  finish_reason: string;
}

// ============================================================================
// Upstream Request
// ============================================================================
function extractLatestUserContent(messages: Message[]): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "user") {
      const { text } = parseMessageContent(messages[i]);
      return text;
    }
  }
  return "";
}

function extractAllImageURLs(messages: Message[]): string[] {
  const allURLs: string[] = [];
  for (const msg of messages) {
    const { imageURLs } = parseMessageContent(msg);
    allURLs.push(...imageURLs);
  }
  return allURLs;
}

// 将所有 system 消息的文本合并到第一条 user 消息中，因为上游 z.ai 不支持 system 角色
function mergeSystemMessages(messages: Message[]): Message[] {
  const systemParts: string[] = [];
  const filtered: Message[] = [];
  for (const msg of messages) {
    if (msg.role === "system") {
      const { text } = parseMessageContent(msg);
      if (text) systemParts.push(text);
    } else {
      filtered.push(msg);
    }
  }

  if (systemParts.length === 0) return messages;

  const systemText = systemParts.join("\n");

  for (let i = 0; i < filtered.length; i++) {
    if (filtered[i].role === "user") {
      const { text, imageURLs } = parseMessageContent(filtered[i]);
      const newText = systemText + "\n\n" + text;
      if (imageURLs.length === 0) {
        filtered[i] = { ...filtered[i], content: newText };
      } else {
        const newContent: ContentPart[] = [{ type: "text", text: newText }];
        for (const imgURL of imageURLs) {
          newContent.push({ type: "image_url", image_url: { url: imgURL } });
        }
        filtered[i] = { ...filtered[i], content: newContent };
      }
      return filtered;
    }
  }

  // 没有 user 消息，将系统提示词作为第一条 user 消息
  return [{ role: "user", content: systemText }, ...filtered];
}

async function makeUpstreamRequest(token: string, messages: Message[], model: string, tools?: unknown[]): Promise<{ resp: Response; targetModel: string } | null> {
  const payload = decodeJWTPayload(token);
  if (!payload) return null;

  const userID = payload.id;
  const chatID = crypto.randomUUID();
  const timestamp = Date.now();
  const requestID = crypto.randomUUID();
  const userMsgID = crypto.randomUUID();

  const targetModel = getTargetModel(model);
  const latestUserContent = extractLatestUserContent(messages);
  const imageURLs = extractAllImageURLs(messages);

  // 上游不支持 system 角色，将系统提示词合并到第一条用户消息中
  messages = mergeSystemMessages(messages);

  const signature = await generateSignature(userID, requestID, latestUserContent, timestamp);

  const url = `https://chat.z.ai/api/v2/chat/completions?timestamp=${timestamp}&requestId=${requestID}&user_id=${userID}&version=0.0.1&platform=web&token=${token}&current_url=https://chat.z.ai/c/${chatID}&pathname=/c/${chatID}&signature_timestamp=${timestamp}`;

  const { enableThinking, enableSearch, enableDeepSearch } = parseModelName(model);
  let autoWebSearch = true; // 智能搜索：始终开启，让模型自行判断是否需要搜索
  const webSearch = enableSearch; // 强制搜索：仅 -search / -deepsearch 模型开启
  if (targetModel === "glm-4.5v" || targetModel === "glm-4.6v" || targetModel === "glm-5v") autoWebSearch = false;

  const flags: string[] = [];

  const mcpServers: string[] = [];
  if (targetModel === "glm-4.6v") {
    mcpServers.push("vlm-image-search", "vlm-image-recognition", "vlm-image-processing");
  }
  if (enableDeepSearch) {
    mcpServers.push("advanced-search");
  }

  const urlToFileID: Record<string, string> = {};
  const filesData: Record<string, unknown>[] = [];
  if (imageURLs.length > 0) {
    const files = await uploadImages(token, imageURLs);
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (i < imageURLs.length) urlToFileID[imageURLs[i]] = f.id;
      filesData.push({
        type: f.type, file: f.file, id: f.id, url: f.url, name: f.name,
        status: f.status, size: f.size, error: f.error, itemId: f.itemId,
        media: f.media, ref_user_msg_id: userMsgID,
      });
    }
  }

  const upstreamMessages = messages.map(msg => {
    const upstream = toUpstreamMessage(msg, urlToFileID);
    // tool 角色消息转换为 assistant 消息（上游不支持 tool role）
    if (msg.role === "tool") upstream.role = "assistant";
    return upstream;
  });

  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const currentDatetime = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const currentDate = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  const currentTime = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  const body: Record<string, unknown> = {
    stream: true,
    model: targetModel,
    messages: upstreamMessages,
    signature_prompt: latestUserContent,
    params: {},
    extra: {},
    features: {
      image_generation: false,
      web_search: webSearch,
      auto_web_search: autoWebSearch,
      preview_mode: enableThinking,
      flags,
      enable_thinking: enableThinking,
    },
    variables: {
      "{{USER_NAME}}": payload.email || "user",
      "{{USER_LOCATION}}": "Unknown",
      "{{CURRENT_DATETIME}}": currentDatetime,
      "{{CURRENT_DATE}}": currentDate,
      "{{CURRENT_TIME}}": currentTime,
      "{{CURRENT_WEEKDAY}}": weekdays[now.getDay()],
      "{{CURRENT_TIMEZONE}}": "Asia/Shanghai",
      "{{USER_LANGUAGE}}": "zh-CN",
    },
    chat_id: chatID,
    id: crypto.randomUUID(),
    current_user_message_id: userMsgID,
    current_user_message_parent_id: null,
    background_tasks: {
      title_generation: true,
      tags_generation: true,
    },
  };

  if (mcpServers.length > 0) body.mcp_servers = mcpServers;
  if (filesData.length > 0) {
    body.files = filesData;
  }
  // 注意：z.ai 不支持 OpenAI 格式的 tools 字段，发送会导致空响应
  // 客户端传入的 tools 仅用于接口兼容，不转发给上游

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "X-FE-Version": feVersion,
      "X-Signature": signature,
      "Content-Type": "application/json",
      "Connection": "keep-alive",
      "Origin": "https://chat.z.ai",
      "Referer": `https://chat.z.ai/c/${crypto.randomUUID()}`,
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    },
    body: JSON.stringify(body),
  });

  return { resp, targetModel };
}

// ============================================================================
// Stream Response Handler
// ============================================================================
async function handleStreamResponse(body: ReadableStream<Uint8Array>, completionID: string, modelName: string): Promise<Response> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const stream = new ReadableStream({
    async start(controller) {
      const reader = body.getReader();
      const searchRefFilter = new SearchRefFilter();
      const thinkingFilter = new ThinkingFilter();
      let pendingSourcesMarkdown = "";
      let pendingImageSearchMarkdown = "";
      let totalContentOutputLength = 0;
      let buffer = "";
      let hasContent = false;

      const sendChunk = (content: string, reasoningContent: string) => {
        const chunk: ChatCompletionChunk = {
          id: completionID,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [{ index: 0, delta: {}, finish_reason: null }],
        };
        if (content) chunk.choices[0].delta.content = content;
        if (reasoningContent) chunk.choices[0].delta.reasoning_content = reasoningContent;
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`));
        hasContent = true;
      };

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            logDebug("[Upstream] %s", line);
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6);
            if (payload === "[DONE]") break;

            let upstream: UpstreamData;
            try { upstream = JSON.parse(payload); } catch { continue; }
            if (!upstream.data) continue;
            if (upstream.data.phase === "done") break;

            // Thinking phase
            if (upstream.data.phase === "thinking" && upstream.data.delta_content) {
              let isNewThinkingRound = false;
              if (thinkingFilter.lastPhase && thinkingFilter.lastPhase !== "thinking") {
                thinkingFilter.resetForNewRound();
                thinkingFilter.thinkingRoundCount++;
                isNewThinkingRound = true;
              }
              thinkingFilter.lastPhase = "thinking";

              let reasoningContent = thinkingFilter.processThinking(upstream.data.delta_content);
              if (isNewThinkingRound && thinkingFilter.thinkingRoundCount > 1 && reasoningContent) {
                reasoningContent = "\n\n" + reasoningContent;
              }
              if (reasoningContent) {
                thinkingFilter.lastOutputChunk = reasoningContent;
                reasoningContent = searchRefFilter.process(reasoningContent);
                if (reasoningContent) sendChunk("", reasoningContent);
              }
              continue;
            }

            if (upstream.data.phase) thinkingFilter.lastPhase = upstream.data.phase;

            const editContent = getEditContent(upstream);

            // Search results
            if (editContent && isSearchResultContent(editContent)) {
              const results = parseSearchResults(editContent);
              if (results && results.length > 0) {
                searchRefFilter.addSearchResults(results);
                pendingSourcesMarkdown = searchRefFilter.getSearchResultsMarkdown();
              }
              continue;
            }

            // Image search
            if (editContent && editContent.includes('"search_image"')) {
              const textBefore = extractTextBeforeGlmBlock(editContent);
              if (textBefore) {
                const processed = searchRefFilter.process(textBefore);
                if (processed) sendChunk(processed, "");
              }
              const results = parseImageSearchResults(editContent);
              if (results && results.length > 0) {
                pendingImageSearchMarkdown = formatImageSearchResults(results);
              }
              continue;
            }

            // MCP content
            if (editContent && editContent.includes('"mcp"')) {
              const textBefore = extractTextBeforeGlmBlock(editContent);
              if (textBefore) {
                const processed = searchRefFilter.process(textBefore);
                if (processed) sendChunk(processed, "");
              }
              continue;
            }

            // Skip tool calls
            if (editContent && isSearchToolCall(editContent, upstream.data.phase)) continue;

            // Output pending markdown
            if (pendingSourcesMarkdown) {
              sendChunk(pendingSourcesMarkdown, "");
              pendingSourcesMarkdown = "";
            }
            if (pendingImageSearchMarkdown) {
              sendChunk(pendingImageSearchMarkdown, "");
              pendingImageSearchMarkdown = "";
            }

            // Flush thinking buffer
            const thinkingRemaining = thinkingFilter.flush();
            if (thinkingRemaining) {
              thinkingFilter.lastOutputChunk = thinkingRemaining;
              const processed = searchRefFilter.process(thinkingRemaining);
              if (processed) sendChunk("", processed);
            }

            // Process content
            let content = "";
            let reasoningContent = "";

            if (upstream.data.phase === "answer" && upstream.data.delta_content) {
              content = upstream.data.delta_content;
            } else if (upstream.data.phase === "answer" && editContent) {
              if (editContent.includes("</details>")) {
                reasoningContent = thinkingFilter.extractIncrementalThinking(editContent);
                const idx = editContent.indexOf("</details>");
                if (idx !== -1) {
                  const afterDetails = editContent.slice(idx + 10);
                  content = afterDetails.startsWith("\n") ? afterDetails.slice(1) : afterDetails;
                  totalContentOutputLength = [...content].length;
                }
              }
            } else if ((upstream.data.phase === "other" || upstream.data.phase === "tool_call") && editContent) {
              const fullContentRunes = [...editContent];
              if (fullContentRunes.length > totalContentOutputLength) {
                content = fullContentRunes.slice(totalContentOutputLength).join("");
                totalContentOutputLength = fullContentRunes.length;
              } else {
                content = editContent;
              }
            }

            if (reasoningContent) {
              reasoningContent = searchRefFilter.process(reasoningContent) + searchRefFilter.flush();
              if (reasoningContent) sendChunk("", reasoningContent);
            }

            if (!content) continue;
            content = searchRefFilter.process(content);
            if (!content) continue;

            if (upstream.data.phase === "answer" && upstream.data.delta_content) {
              totalContentOutputLength += [...content].length;
            }
            sendChunk(content, "");
          }
        }

        // Flush remaining
        const remaining = searchRefFilter.flush();
        if (remaining) sendChunk(remaining, "");

        if (!hasContent) logError("Stream response 200 but no content received");

        // Final chunk
        const finalChunk: ChatCompletionChunk = {
          id: completionID,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        };
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      } catch (e) {
        logError("Stream error: %s", e);
        controller.error(e);
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    },
  });
}

// ============================================================================
// Non-Stream Response Handler
// ============================================================================
async function handleNonStreamResponse(body: ReadableStream<Uint8Array>, completionID: string, modelName: string): Promise<Response> {
  const decoder = new TextDecoder();
  const reader = body.getReader();
  const chunks: string[] = [];
  const reasoningChunks: string[] = [];
  const thinkingFilter = new ThinkingFilter();
  const searchRefFilter = new SearchRefFilter();
  let hasThinking = false;
  let pendingSourcesMarkdown = "";
  let pendingImageSearchMarkdown = "";
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const payload = line.slice(6);
        if (payload === "[DONE]") break;

        let upstream: UpstreamData;
        try { upstream = JSON.parse(payload); } catch { continue; }
        if (!upstream.data) continue;
        if (upstream.data.phase === "done") break;

        if (upstream.data.phase === "thinking" && upstream.data.delta_content) {
          if (thinkingFilter.lastPhase && thinkingFilter.lastPhase !== "thinking") {
            thinkingFilter.resetForNewRound();
            thinkingFilter.thinkingRoundCount++;
            if (thinkingFilter.thinkingRoundCount > 1) reasoningChunks.push("\n\n");
          }
          thinkingFilter.lastPhase = "thinking";
          hasThinking = true;
          const reasoningContent = thinkingFilter.processThinking(upstream.data.delta_content);
          if (reasoningContent) {
            thinkingFilter.lastOutputChunk = reasoningContent;
            reasoningChunks.push(reasoningContent);
          }
          continue;
        }

        if (upstream.data.phase) thinkingFilter.lastPhase = upstream.data.phase;

        const editContent = getEditContent(upstream);

        if (editContent && isSearchResultContent(editContent)) {
          const results = parseSearchResults(editContent);
          if (results && results.length > 0) {
            searchRefFilter.addSearchResults(results);
            pendingSourcesMarkdown = searchRefFilter.getSearchResultsMarkdown();
          }
          continue;
        }

        if (editContent && editContent.includes('"search_image"')) {
          const textBefore = extractTextBeforeGlmBlock(editContent);
          if (textBefore) chunks.push(textBefore);
          const results = parseImageSearchResults(editContent);
          if (results && results.length > 0) {
            pendingImageSearchMarkdown = formatImageSearchResults(results);
          }
          continue;
        }

        if (editContent && editContent.includes('"mcp"')) {
          const textBefore = extractTextBeforeGlmBlock(editContent);
          if (textBefore) chunks.push(textBefore);
          continue;
        }

        if (editContent && isSearchToolCall(editContent, upstream.data.phase)) continue;

        if (pendingSourcesMarkdown) {
          if (hasThinking) reasoningChunks.push(pendingSourcesMarkdown);
          else chunks.push(pendingSourcesMarkdown);
          pendingSourcesMarkdown = "";
        }
        if (pendingImageSearchMarkdown) {
          chunks.push(pendingImageSearchMarkdown);
          pendingImageSearchMarkdown = "";
        }

        let content = "";
        if (upstream.data.phase === "answer" && upstream.data.delta_content) {
          content = upstream.data.delta_content;
        } else if (upstream.data.phase === "answer" && editContent) {
          if (editContent.includes("</details>")) {
            const reasoningContent = thinkingFilter.extractIncrementalThinking(editContent);
            if (reasoningContent) reasoningChunks.push(reasoningContent);
            const idx = editContent.indexOf("</details>");
            if (idx !== -1) {
              const afterDetails = editContent.slice(idx + 10);
              content = afterDetails.startsWith("\n") ? afterDetails.slice(1) : afterDetails;
            }
          }
        } else if ((upstream.data.phase === "other" || upstream.data.phase === "tool_call") && editContent) {
          content = editContent;
        }

        if (content) chunks.push(content);
      }
    }
  } catch (e) {
    logError("Non-stream error: %s", e);
  }

  let fullContent = chunks.join("");
  fullContent = searchRefFilter.process(fullContent) + searchRefFilter.flush();
  let fullReasoning = reasoningChunks.join("");
  fullReasoning = searchRefFilter.process(fullReasoning) + searchRefFilter.flush();

  if (!fullContent) logError("Non-stream response 200 but no content received");

  const response: ChatCompletionResponse = {
    id: completionID,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: modelName,
    choices: [{
      index: 0,
      message: { role: "assistant", content: fullContent, reasoning_content: fullReasoning || undefined },
      finish_reason: "stop",
    }],
  };

  return new Response(JSON.stringify(response), {
    headers: { "Content-Type": "application/json" },
  });
}

// ============================================================================
// HTTP Handlers
// ============================================================================
async function handleChatCompletions(req: Request): Promise<Response> {
  let token = req.headers.get("Authorization")?.replace("Bearer ", "") || "";
  if (!token) return new Response("Unauthorized", { status: 401 });

  if (token === "free") {
    try {
      token = await getAnonymousToken();
    } catch (e) {
      logError("Failed to get anonymous token: %s", e);
      return new Response("Failed to get anonymous token", { status: 500 });
    }
  }

  let body: { model?: string; messages: Message[]; stream?: boolean; tools?: unknown[] };
  try {
    body = await req.json();
  } catch {
    return new Response("Invalid request", { status: 400 });
  }

  const model = body.model || "GLM-5";
  const result = await makeUpstreamRequest(token, body.messages, model, body.tools);
  if (!result) return new Response("Invalid token", { status: 403 });

  const { resp, targetModel } = result;
  if (!resp.ok) {
    const errBody = await resp.text();
    logError("Upstream error: status=%d, body=%s", resp.status, errBody.slice(0, 500));
    return new Response("Upstream error", { status: resp.status });
  }

  const completionID = `chatcmpl-${crypto.randomUUID().slice(0, 29)}`;

  if (body.stream) {
    return handleStreamResponse(resp.body!, completionID, targetModel);
  } else {
    return handleNonStreamResponse(resp.body!, completionID, targetModel);
  }
}

function handleModels(): Response {
  const models = MODEL_LIST.map(id => ({ id, object: "model", owned_by: "z.ai" }));
  return new Response(JSON.stringify({ object: "list", data: models }), {
    headers: { "Content-Type": "application/json" },
  });
}

// ============================================================================
// Anthropic Messages API Types
// ============================================================================
interface AnthropicRequest {
  model: string;
  max_tokens: number;
  messages: AnthropicMessage[];
  system?: string | AnthropicContentBlock[];
  stream?: boolean;
  temperature?: number;
  tools?: AnthropicTool[];
  thinking?: { type: string; budget_tokens?: number };
  stop_sequences?: string[];
}

interface AnthropicMessage {
  role: string;
  content: string | AnthropicContentBlock[];
}

interface AnthropicContentBlock {
  type: string;
  text?: string;
  source?: { type: string; media_type: string; data: string; url?: string };
  id?: string;
  name?: string;
  input?: unknown;
  tool_use_id?: string;
  content?: string | AnthropicContentBlock[];
  thinking?: string;
}

interface AnthropicTool {
  name: string;
  description?: string;
  input_schema: unknown;
}

// ============================================================================
// Anthropic Request Conversion
// ============================================================================
function convertAnthropicToInternal(req: AnthropicRequest): { messages: Message[]; model: string; hasTools: boolean } {
  const hasTools = (req.tools?.length ?? 0) > 0;
  const messages: Message[] = [];

  // Build tool_use_id → {name, arguments} map for tool_result conversion
  const toolUseMap = new Map<string, { name: string; arguments: string }>();
  if (hasTools) {
    for (const msg of req.messages) {
      if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === "tool_use" && block.id) {
            toolUseMap.set(block.id, {
              name: block.name || "",
              arguments: block.input ? JSON.stringify(block.input) : "{}",
            });
          }
        }
      }
    }
  }

  // Build system prompt (original system + tool definitions)
  let systemText = "";
  if (req.system) {
    if (typeof req.system === "string") {
      systemText = req.system;
    } else if (Array.isArray(req.system)) {
      for (const block of req.system) {
        if (block.type === "text" && block.text) systemText += block.text;
      }
    }
  }

  // Inject tool definitions into system prompt
  if (hasTools && req.tools) {
    const toolPrompt = formatToolsSystemPrompt(req.tools);
    systemText = systemText ? toolPrompt + "\n\n" + systemText : toolPrompt;
  }

  if (systemText) {
    messages.push({ role: "system", content: systemText });
  }

  // Convert messages
  for (const msg of req.messages) {
    const converted = convertAnthropicMessageWithTools(msg, hasTools, toolUseMap);
    for (const m of converted) {
      const contentStr = typeof m.content === "string" ? m.content : JSON.stringify(m.content);
      logInfo("[Anthropic] Converted msg: role=%s, contentLen=%d, contentTail=%s", m.role, contentStr.length, contentStr.slice(-200));
    }
    messages.push(...converted);
  }

  // Determine model name
  let model = req.model || "GLM-5";
  if (req.thinking?.type === "enabled" && !model.endsWith("-thinking")) {
    model = model + "-thinking";
  }

  // Tools are NOT forwarded to upstream (z.ai doesn't support them).
  // They are injected as XML system prompt instead.
  return { messages, model, hasTools };
}

function convertAnthropicMessageWithTools(msg: AnthropicMessage, hasTools: boolean, toolUseMap: Map<string, { name: string; arguments: string }>): Message[] {
  if (typeof msg.content === "string") {
    return [{ role: msg.role, content: msg.content }];
  }

  const textParts: string[] = [];
  const imageParts: ContentPart[] = [];
  let hasImages = false;
  const toolUseCalls: Record<string, unknown>[] = [];

  for (const block of msg.content) {
    switch (block.type) {
      case "text":
        textParts.push(block.text || "");
        break;
      case "image": {
        if (!block.source) break;
        if (block.source.type === "base64") {
          const dataURI = `data:${block.source.media_type};base64,${block.source.data}`;
          imageParts.push({ type: "image_url", image_url: { url: dataURI } });
          hasImages = true;
        } else if (block.source.type === "url" && block.source.url) {
          imageParts.push({ type: "image_url", image_url: { url: block.source.url } });
          hasImages = true;
        }
        break;
      }
      case "tool_use": {
        if (hasTools) {
          logDebug("[Anthropic] Converting tool_use block: name=%s", block.name);
          toolUseCalls.push({ name: block.name, arguments: block.input ?? {} });
        }
        break;
      }
      case "tool_result": {
        if (hasTools) {
          let toolContent = "";
          if (typeof block.content === "string") {
            toolContent = block.content;
          } else if (Array.isArray(block.content)) {
            for (const b of block.content) {
              if (b.type === "text" && b.text) toolContent += b.text;
            }
          }
          const toolUseID = block.tool_use_id || "";
          const info = toolUseMap.get(toolUseID);
          const toolName = info?.name || "";
          const toolArgs = info?.arguments || "{}";
          logInfo("[Anthropic] Converting tool_result block: toolUseID=%s, toolName=%s, contentLen=%d", toolUseID, toolName, toolContent.length);
          logInfo("[Anthropic] tool_result content (first 200): %s", toolContent.slice(0, 200));
          const toolResultXML = formatToolResultXML(toolName, toolArgs, toolContent);
          logInfo("[Anthropic] tool_result XML (first 300): %s", toolResultXML.slice(0, 300));
          textParts.push(toolResultXML);
        } else {
          let toolContent = "";
          if (typeof block.content === "string") {
            toolContent = block.content;
          } else if (Array.isArray(block.content)) {
            for (const b of block.content) {
              if (b.type === "text" && b.text) toolContent += b.text;
            }
          }
          return [{ role: "tool", content: toolContent }];
        }
        break;
      }
    }
  }

  // Format collected tool_use blocks as Toolify-style XML
  if (toolUseCalls.length > 0) {
    const xml = formatAssistantToolCallsXML(toolUseCalls);
    logDebug("[Anthropic] Formatted %d tool_use blocks as XML, length=%d", toolUseCalls.length, xml.length);
    if (xml) textParts.push(xml);
  }

  const combinedText = textParts.join("");

  if (hasImages) {
    const parts: ContentPart[] = [];
    if (combinedText) parts.push({ type: "text", text: combinedText });
    parts.push(...imageParts);
    if (parts.length > 0) return [{ role: msg.role, content: parts }];
  }

  if (combinedText) return [{ role: msg.role, content: combinedText }];
  return [{ role: msg.role, content: "" }];
}

// ============================================================================
// Anthropic Messages Handler
// ============================================================================
async function handleAnthropicMessages(req: Request): Promise<Response> {
  let token = req.headers.get("Authorization")?.replace("Bearer ", "") || "";
  // Anthropic SDK uses x-api-key header
  if (!token) token = req.headers.get("x-api-key") || "";
  if (!token) {
    return new Response(JSON.stringify({
      type: "error",
      error: { type: "authentication_error", message: "Missing API key" },
    }), { status: 401, headers: { "Content-Type": "application/json" } });
  }

  if (token === "free") {
    try {
      token = await getAnonymousToken();
    } catch (e) {
      logError("Failed to get anonymous token: %s", e);
      return new Response(JSON.stringify({
        type: "error",
        error: { type: "api_error", message: "Failed to get anonymous token" },
      }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  let body: AnthropicRequest;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({
      type: "error",
      error: { type: "invalid_request_error", message: "Invalid request body" },
    }), { status: 400, headers: { "Content-Type": "application/json" } });
  }

  const { messages, model, hasTools } = convertAnthropicToInternal(body);
  logInfo("[Anthropic] model=%s, hasTools=%s, toolCount=%d, messageCount=%d, stream=%s",
    model, hasTools, body.tools?.length ?? 0, messages.length, body.stream ?? false);
  if (hasTools) {
    logInfo("[Anthropic] TRIGGER_SIGNAL=%s", TRIGGER_SIGNAL);
    // Log system prompt (first message if system role)
    if (messages.length > 0 && messages[0].role === "system") {
      const sysContent = typeof messages[0].content === "string" ? messages[0].content : JSON.stringify(messages[0].content);
      logDebug("[Anthropic] System prompt length=%d, first 500 chars: %s", sysContent.length, sysContent.slice(0, 500));
    }
  }
  const result = await makeUpstreamRequest(token, messages, model);
  if (!result) {
    return new Response(JSON.stringify({
      type: "error",
      error: { type: "authentication_error", message: "Invalid token" },
    }), { status: 403, headers: { "Content-Type": "application/json" } });
  }

  const { resp, targetModel } = result;
  if (!resp.ok) {
    const errBody = await resp.text();
    logError("Upstream error: status=%d, body=%s", resp.status, errBody.slice(0, 500));
    return new Response(JSON.stringify({
      type: "error",
      error: { type: "api_error", message: "Upstream error" },
    }), { status: resp.status, headers: { "Content-Type": "application/json" } });
  }

  const messageID = `msg_${crypto.randomUUID().slice(0, 29)}`;

  if (body.stream) {
    return handleAnthropicStreamResponse(resp.body!, messageID, targetModel, hasTools);
  } else {
    return handleAnthropicNonStreamResponse(resp.body!, messageID, targetModel, hasTools);
  }
}

// ============================================================================
// Anthropic Non-Stream Response
// ============================================================================
async function handleAnthropicNonStreamResponse(body: ReadableStream<Uint8Array>, messageID: string, modelName: string, hasTools: boolean): Promise<Response> {
  const decoder = new TextDecoder();
  const reader = body.getReader();
  const chunks: string[] = [];
  const reasoningChunks: string[] = [];
  const thinkingFilter = new ThinkingFilter();
  const searchRefFilter = new SearchRefFilter();
  let hasThinking = false;
  let pendingSourcesMarkdown = "";
  let pendingImageSearchMarkdown = "";
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const payload = line.slice(6);
        if (payload === "[DONE]") break;

        let upstream: UpstreamData;
        try { upstream = JSON.parse(payload); } catch { continue; }
        if (!upstream.data) continue;
        if (upstream.data.phase === "done") break;

        if (upstream.data.phase === "thinking" && upstream.data.delta_content) {
          if (thinkingFilter.lastPhase && thinkingFilter.lastPhase !== "thinking") {
            thinkingFilter.resetForNewRound();
            thinkingFilter.thinkingRoundCount++;
            if (thinkingFilter.thinkingRoundCount > 1) reasoningChunks.push("\n\n");
          }
          thinkingFilter.lastPhase = "thinking";
          hasThinking = true;
          const reasoningContent = thinkingFilter.processThinking(upstream.data.delta_content);
          if (reasoningContent) {
            thinkingFilter.lastOutputChunk = reasoningContent;
            reasoningChunks.push(reasoningContent);
          }
          continue;
        }

        if (upstream.data.phase) thinkingFilter.lastPhase = upstream.data.phase;

        const editContent = getEditContent(upstream);

        if (editContent && isSearchResultContent(editContent)) {
          const results = parseSearchResults(editContent);
          if (results && results.length > 0) {
            searchRefFilter.addSearchResults(results);
            pendingSourcesMarkdown = searchRefFilter.getSearchResultsMarkdown();
          }
          continue;
        }

        if (editContent && editContent.includes('"search_image"')) {
          const textBefore = extractTextBeforeGlmBlock(editContent);
          if (textBefore) chunks.push(textBefore);
          const results = parseImageSearchResults(editContent);
          if (results && results.length > 0) {
            pendingImageSearchMarkdown = formatImageSearchResults(results);
          }
          continue;
        }

        if (editContent && editContent.includes('"mcp"')) {
          const textBefore = extractTextBeforeGlmBlock(editContent);
          if (textBefore) chunks.push(textBefore);
          continue;
        }

        if (editContent && isSearchToolCall(editContent, upstream.data.phase)) continue;

        if (pendingSourcesMarkdown) {
          if (hasThinking) reasoningChunks.push(pendingSourcesMarkdown);
          else chunks.push(pendingSourcesMarkdown);
          pendingSourcesMarkdown = "";
        }
        if (pendingImageSearchMarkdown) {
          chunks.push(pendingImageSearchMarkdown);
          pendingImageSearchMarkdown = "";
        }

        let content = "";
        if (upstream.data.phase === "answer" && upstream.data.delta_content) {
          content = upstream.data.delta_content;
        } else if (upstream.data.phase === "answer" && editContent) {
          if (editContent.includes("</details>")) {
            const reasoningContent = thinkingFilter.extractIncrementalThinking(editContent);
            if (reasoningContent) reasoningChunks.push(reasoningContent);
            const idx = editContent.indexOf("</details>");
            if (idx !== -1) {
              const afterDetails = editContent.slice(idx + 10);
              content = afterDetails.startsWith("\n") ? afterDetails.slice(1) : afterDetails;
            }
          }
        } else if ((upstream.data.phase === "other" || upstream.data.phase === "tool_call") && editContent) {
          content = editContent;
        }

        if (content) chunks.push(content);
      }
    }
  } catch (e) {
    logError("Non-stream error: %s", e);
  }

  let fullContent = chunks.join("");
  fullContent = searchRefFilter.process(fullContent) + searchRefFilter.flush();
  let fullReasoning = reasoningChunks.join("");
  fullReasoning = searchRefFilter.process(fullReasoning) + searchRefFilter.flush();

  // Extract tool calls from content if tools were requested
  let parsedToolCalls: ParsedToolCall[] = [];
  if (hasTools) {
    logInfo("[Anthropic-NonStream] Full content length=%d", fullContent.length);
    logInfo("[Anthropic-NonStream] Contains trigger? %s, contains <function_calls>? %s",
      fullContent.includes(TRIGGER_SIGNAL), fullContent.includes("<function_calls>"));
    const tail = fullContent.slice(-500);
    logInfo("[Anthropic-NonStream] Content tail (last 500): %s", tail);

    parsedToolCalls = parseFunctionCallsXML(fullContent);
    logInfo("[Anthropic-NonStream] Parsed tool calls: %d", parsedToolCalls.length);
    for (const tc of parsedToolCalls) {
      logInfo("[Anthropic-NonStream] Tool call: name=%s, argsLen=%d", tc.name, tc.arguments.length);
    }
    const pos = findTriggerSignalPosition(fullContent);
    logInfo("[Anthropic-NonStream] Trigger position: %d", pos);
    if (pos >= 0) {
      fullContent = fullContent.slice(0, pos).trim();
    }
  }

  // Build content blocks
  const contentBlocks: AnthropicContentBlock[] = [];
  if (fullReasoning) {
    contentBlocks.push({ type: "thinking", thinking: fullReasoning });
  }
  if (fullContent) {
    contentBlocks.push({ type: "text", text: fullContent });
  }

  // Add tool_use content blocks
  for (let i = 0; i < parsedToolCalls.length; i++) {
    const tc = parsedToolCalls[i];
    const toolID = `toolu_${crypto.randomUUID().slice(0, 8)}_${i}`;
    let inputParsed: unknown = {};
    try { inputParsed = JSON.parse(tc.arguments); } catch { /* use empty object */ }
    contentBlocks.push({
      type: "tool_use",
      id: toolID,
      name: tc.name,
      input: inputParsed,
    });
  }

  // If no content blocks, add empty text
  if (contentBlocks.length === 0) {
    contentBlocks.push({ type: "text", text: "" });
  }

  const stopReason = parsedToolCalls.length > 0 ? "tool_use" : "end_turn";
  const inputTokens = Math.max(1, Math.floor(fullContent.length / 4));
  const outputTokens = Math.max(1, Math.floor((fullContent.length + fullReasoning.length) / 4));

  const response = {
    id: messageID,
    type: "message",
    role: "assistant",
    content: contentBlocks,
    model: modelName,
    stop_reason: stopReason,
    stop_sequence: null,
    usage: { input_tokens: inputTokens, output_tokens: outputTokens },
  };

  return new Response(JSON.stringify(response), {
    headers: { "Content-Type": "application/json" },
  });
}

// ============================================================================
// Anthropic Stream Response
// ============================================================================
async function handleAnthropicStreamResponse(body: ReadableStream<Uint8Array>, messageID: string, modelName: string, hasTools: boolean): Promise<Response> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const stream = new ReadableStream({
    async start(controller) {
      const reader = body.getReader();
      const searchRefFilter = new SearchRefFilter();
      const thinkingFilter = new ThinkingFilter();
      let pendingSourcesMarkdown = "";
      let pendingImageSearchMarkdown = "";
      let totalContentOutputLength = 0;
      let buffer = "";

      let contentBlockIndex = 0;
      let thinkingBlockStarted = false;
      let textBlockStarted = false;
      let outputTokens = 0;
      const toolContentBuffer: string[] = []; // buffer text when hasTools for end-of-stream parsing
      const allToolCalls: ParsedToolCall[] = [];

      const writeEvent = (eventType: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`));
      };

      const startThinkingBlock = () => {
        if (!thinkingBlockStarted) {
          writeEvent("content_block_start", {
            type: "content_block_start",
            index: contentBlockIndex,
            content_block: { type: "thinking", thinking: "" },
          });
          thinkingBlockStarted = true;
        }
      };

      const stopThinkingBlock = () => {
        if (thinkingBlockStarted) {
          writeEvent("content_block_stop", {
            type: "content_block_stop",
            index: contentBlockIndex,
          });
          contentBlockIndex++;
          thinkingBlockStarted = false;
        }
      };

      const startTextBlock = () => {
        if (!textBlockStarted) {
          stopThinkingBlock();
          writeEvent("content_block_start", {
            type: "content_block_start",
            index: contentBlockIndex,
            content_block: { type: "text", text: "" },
          });
          textBlockStarted = true;
        }
      };

      const sendThinkingDelta = (thinking: string) => {
        startThinkingBlock();
        writeEvent("content_block_delta", {
          type: "content_block_delta",
          index: contentBlockIndex,
          delta: { type: "thinking_delta", thinking },
        });
      };

      const sendTextDelta = (text: string) => {
        startTextBlock();
        writeEvent("content_block_delta", {
          type: "content_block_delta",
          index: contentBlockIndex,
          delta: { type: "text_delta", text },
        });
      };

      try {
        // Send message_start
        writeEvent("message_start", {
          type: "message_start",
          message: {
            id: messageID,
            type: "message",
            role: "assistant",
            content: [],
            model: modelName,
            stop_reason: null,
            stop_sequence: null,
            usage: { input_tokens: 0, output_tokens: 0 },
          },
        });

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            logDebug("[Upstream] %s", line);
            if (!line.startsWith("data: ")) continue;
            const payload = line.slice(6);
            if (payload === "[DONE]") break;

            let upstream: UpstreamData;
            try { upstream = JSON.parse(payload); } catch { continue; }
            if (!upstream.data) continue;
            if (upstream.data.phase === "done") break;

            // Log every upstream event phase when tools are present
            if (hasTools) {
              const dc = upstream.data.delta_content;
              const ec = upstream.data.edit_content;
              logDebug("[Anthropic-Stream-Loop] phase=%s, delta_content_len=%d, edit_content_len=%d",
                upstream.data.phase,
                dc ? dc.length : 0,
                ec ? ec.length : 0);
            }

            // Thinking phase
            if (upstream.data.phase === "thinking" && upstream.data.delta_content) {
              let isNewThinkingRound = false;
              if (thinkingFilter.lastPhase && thinkingFilter.lastPhase !== "thinking") {
                thinkingFilter.resetForNewRound();
                thinkingFilter.thinkingRoundCount++;
                isNewThinkingRound = true;
              }
              thinkingFilter.lastPhase = "thinking";

              let reasoningContent = thinkingFilter.processThinking(upstream.data.delta_content);
              if (isNewThinkingRound && thinkingFilter.thinkingRoundCount > 1 && reasoningContent) {
                reasoningContent = "\n\n" + reasoningContent;
              }
              if (reasoningContent) {
                thinkingFilter.lastOutputChunk = reasoningContent;
                reasoningContent = searchRefFilter.process(reasoningContent);
                if (reasoningContent) {
                  sendThinkingDelta(reasoningContent);
                  outputTokens += Math.floor(reasoningContent.length / 4);
                }
              }
              continue;
            }

            if (upstream.data.phase) thinkingFilter.lastPhase = upstream.data.phase;

            const editContent = getEditContent(upstream);

            if (editContent && isSearchResultContent(editContent)) {
              const results = parseSearchResults(editContent);
              if (results && results.length > 0) {
                searchRefFilter.addSearchResults(results);
                pendingSourcesMarkdown = searchRefFilter.getSearchResultsMarkdown();
              }
              continue;
            }

            if (editContent && editContent.includes('"search_image"')) {
              const textBefore = extractTextBeforeGlmBlock(editContent);
              if (textBefore) {
                const processed = searchRefFilter.process(textBefore);
                if (processed) {
                  sendTextDelta(processed);
                  outputTokens += Math.floor(processed.length / 4);
                }
              }
              const results = parseImageSearchResults(editContent);
              if (results && results.length > 0) {
                pendingImageSearchMarkdown = formatImageSearchResults(results);
              }
              continue;
            }

            if (editContent && editContent.includes('"mcp"')) {
              const textBefore = extractTextBeforeGlmBlock(editContent);
              if (textBefore) {
                const processed = searchRefFilter.process(textBefore);
                if (processed) {
                  sendTextDelta(processed);
                  outputTokens += Math.floor(processed.length / 4);
                }
              }
              continue;
            }

            if (editContent && isSearchToolCall(editContent, upstream.data.phase)) continue;

            if (pendingSourcesMarkdown) {
              sendTextDelta(pendingSourcesMarkdown);
              outputTokens += Math.floor(pendingSourcesMarkdown.length / 4);
              pendingSourcesMarkdown = "";
            }
            if (pendingImageSearchMarkdown) {
              sendTextDelta(pendingImageSearchMarkdown);
              outputTokens += Math.floor(pendingImageSearchMarkdown.length / 4);
              pendingImageSearchMarkdown = "";
            }

            // Flush thinking buffer
            const thinkingRemaining = thinkingFilter.flush();
            if (thinkingRemaining) {
              thinkingFilter.lastOutputChunk = thinkingRemaining;
              const processed = searchRefFilter.process(thinkingRemaining);
              if (processed) {
                sendThinkingDelta(processed);
                outputTokens += Math.floor(processed.length / 4);
              }
            }

            let content = "";
            let reasoningContent = "";

            if (upstream.data.phase === "answer" && upstream.data.delta_content) {
              content = upstream.data.delta_content;
            } else if (upstream.data.phase === "answer" && editContent) {
              if (editContent.includes("</details>")) {
                reasoningContent = thinkingFilter.extractIncrementalThinking(editContent);
                const idx = editContent.indexOf("</details>");
                if (idx !== -1) {
                  const afterDetails = editContent.slice(idx + 10);
                  content = afterDetails.startsWith("\n") ? afterDetails.slice(1) : afterDetails;
                  totalContentOutputLength = [...content].length;
                }
              }
            } else if ((upstream.data.phase === "other" || upstream.data.phase === "tool_call") && editContent) {
              const fullContentRunes = [...editContent];
              if (fullContentRunes.length > totalContentOutputLength) {
                content = fullContentRunes.slice(totalContentOutputLength).join("");
                totalContentOutputLength = fullContentRunes.length;
              } else {
                content = editContent;
              }
            }

            if (reasoningContent) {
              reasoningContent = searchRefFilter.process(reasoningContent) + searchRefFilter.flush();
              if (reasoningContent) {
                sendThinkingDelta(reasoningContent);
                outputTokens += Math.floor(reasoningContent.length / 4);
              }
            }

            if (!content) continue;
            content = searchRefFilter.process(content);
            if (!content) continue;

            if (upstream.data.phase === "answer" && upstream.data.delta_content) {
              totalContentOutputLength += [...content].length;
            }
            // When tools are present, buffer content for end-of-stream parsing
            if (hasTools) {
              toolContentBuffer.push(content);
              logDebug("[Anthropic-Stream] Buffered content chunk, len=%d, totalBufferChunks=%d", content.length, toolContentBuffer.length);
            } else {
              sendTextDelta(content);
              outputTokens += Math.floor(content.length / 4);
            }
          }
        }

        // Flush remaining search ref
        const remaining = searchRefFilter.flush();
        if (remaining) {
          if (hasTools) {
            toolContentBuffer.push(remaining);
          } else {
            sendTextDelta(remaining);
            outputTokens += Math.floor(remaining.length / 4);
          }
        }

        // Parse buffered content for tool calls when tools are present
        if (hasTools && toolContentBuffer.length > 0) {
          const bufferedContent = toolContentBuffer.join("");
          logInfo("[Anthropic-Stream] Tool buffer complete: totalLen=%d, chunks=%d", bufferedContent.length, toolContentBuffer.length);
          logInfo("[Anthropic-Stream] TRIGGER_SIGNAL=%s", TRIGGER_SIGNAL);
          logInfo("[Anthropic-Stream] Buffer contains trigger? %s", bufferedContent.includes(TRIGGER_SIGNAL));
          logInfo("[Anthropic-Stream] Buffer contains <function_calls>? %s", bufferedContent.includes("<function_calls>"));
          // Log last 500 chars to see what model actually output
          const tail = bufferedContent.slice(-500);
          logInfo("[Anthropic-Stream] Buffer tail (last 500): %s", tail);

          allToolCalls.push(...parseFunctionCallsXML(bufferedContent));
          logInfo("[Anthropic-Stream] Parsed tool calls count: %d", allToolCalls.length);
          for (const tc of allToolCalls) {
            logInfo("[Anthropic-Stream] Tool call: name=%s, argsLen=%d", tc.name, tc.arguments.length);
          }

          let textContent = bufferedContent;
          const pos = findTriggerSignalPosition(bufferedContent);
          logInfo("[Anthropic-Stream] Trigger signal position: %d", pos);
          if (pos >= 0) {
            textContent = bufferedContent.slice(0, pos).trim();
          }
          if (textContent) {
            logInfo("[Anthropic-Stream] Emitting text content, len=%d", textContent.length);
            sendTextDelta(textContent);
            outputTokens += Math.floor(textContent.length / 4);
          }
        } else if (hasTools) {
          logWarn("[Anthropic-Stream] hasTools=true but toolContentBuffer is empty!");
        }

        // Close text block if open
        if (textBlockStarted) {
          writeEvent("content_block_stop", {
            type: "content_block_stop",
            index: contentBlockIndex,
          });
          contentBlockIndex++;
          textBlockStarted = false;
        } else {
          stopThinkingBlock();
        }

        // Emit tool_use content blocks
        logInfo("[Anthropic-Stream] Emitting %d tool_use blocks", allToolCalls.length);
        for (let i = 0; i < allToolCalls.length; i++) {
          const tc = allToolCalls[i];
          const toolID = `toolu_${crypto.randomUUID().slice(0, 8)}_${i}`;

          writeEvent("content_block_start", {
            type: "content_block_start",
            index: contentBlockIndex,
            content_block: { type: "tool_use", id: toolID, name: tc.name, input: {} },
          });

          writeEvent("content_block_delta", {
            type: "content_block_delta",
            index: contentBlockIndex,
            delta: { type: "input_json_delta", partial_json: tc.arguments },
          });

          writeEvent("content_block_stop", {
            type: "content_block_stop",
            index: contentBlockIndex,
          });
          contentBlockIndex++;
        }

        if (outputTokens === 0) outputTokens = 1;

        const stopReason = allToolCalls.length > 0 ? "tool_use" : "end_turn";
        logInfo("[Anthropic-Stream] Final: stopReason=%s, outputTokens=%d, toolCallsCount=%d", stopReason, outputTokens, allToolCalls.length);

        // message_delta
        writeEvent("message_delta", {
          type: "message_delta",
          delta: { stop_reason: stopReason, stop_sequence: null },
          usage: { output_tokens: outputTokens },
        });

        // message_stop
        writeEvent("message_stop", { type: "message_stop" });

        controller.close();
      } catch (e) {
        logError("Anthropic stream error: %s", e);
        controller.error(e);
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    },
  });
}

// ============================================================================
// Main Server
// ============================================================================
initLogger();
startVersionUpdater();

logInfo("Server starting on :%d", PORT);

Deno.serve({ port: PORT }, async (req) => {
  const url = new URL(req.url);

  if (url.pathname === "/v1/models") {
    return handleModels();
  }

  if (url.pathname === "/v1/chat/completions") {
    return handleChatCompletions(req);
  }

  if (url.pathname === "/v1/messages") {
    return handleAnthropicMessages(req);
  }

  return new Response("Not Found", { status: 404 });
});
