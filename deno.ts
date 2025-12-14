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
  "GLM-4.5": "0727-360B-API",
  "GLM-4.6": "GLM-4-6-API-V1",
  "GLM-4.5-V": "glm-4.5v",
  "GLM-4.6-V": "glm-4.6v",
  "GLM-4.5-Air": "0727-106B-API",
  "0808-360B-DR": "0808-360B-DR",
};

const MODEL_LIST = [
  "GLM-4.5", "GLM-4.6", "GLM-4.5-thinking", "GLM-4.6-thinking",
  "GLM-4.5-V", "GLM-4.6-V", "GLM-4.6-V-thinking", "GLM-4.5-Air", "0808-360B-DR",
];

function parseModelName(model: string) {
  let baseModel = model;
  let enableThinking = false;
  let enableSearch = false;
  while (true) {
    if (baseModel.endsWith("-thinking")) {
      enableThinking = true;
      baseModel = baseModel.slice(0, -9);
    } else if (baseModel.endsWith("-search")) {
      enableSearch = true;
      baseModel = baseModel.slice(0, -7);
    } else break;
  }
  return { baseModel, enableThinking, enableSearch };
}

function getTargetModel(model: string): string {
  const { baseModel } = parseModelName(model);
  return BASE_MODEL_MAPPING[baseModel] || model;
}

// ============================================================================
// JWT Decoder
// ============================================================================
interface JWTPayload { id: string }

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

async function makeUpstreamRequest(token: string, messages: Message[], model: string): Promise<{ resp: Response; targetModel: string } | null> {
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
  const signature = await generateSignature(userID, requestID, latestUserContent, timestamp);

  const url = `https://chat.z.ai/api/v2/chat/completions?timestamp=${timestamp}&requestId=${requestID}&user_id=${userID}&version=0.0.1&platform=web&token=${token}&current_url=https://chat.z.ai/c/${chatID}&pathname=/c/${chatID}&signature_timestamp=${timestamp}`;

  const { enableThinking, enableSearch } = parseModelName(model);
  let autoWebSearch = enableSearch;
  if (targetModel === "glm-4.5v" || targetModel === "glm-4.6v") autoWebSearch = false;

  const mcpServers: string[] = [];
  if (targetModel === "glm-4.6v") {
    mcpServers.push("vlm-image-search", "vlm-image-recognition", "vlm-image-processing");
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

  const upstreamMessages = messages.map(msg => toUpstreamMessage(msg, urlToFileID));

  const body: Record<string, unknown> = {
    stream: true,
    model: targetModel,
    messages: upstreamMessages,
    signature_prompt: latestUserContent,
    params: {},
    features: {
      image_generation: false,
      web_search: false,
      auto_web_search: autoWebSearch,
      preview_mode: true,
      enable_thinking: enableThinking,
    },
    chat_id: chatID,
    id: crypto.randomUUID(),
  };

  if (mcpServers.length > 0) body.mcp_servers = mcpServers;
  if (filesData.length > 0) {
    body.files = filesData;
    body.current_user_message_id = userMsgID;
  }

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

  let body: { model?: string; messages: Message[]; stream?: boolean };
  try {
    body = await req.json();
  } catch {
    return new Response("Invalid request", { status: 400 });
  }

  const model = body.model || "GLM-4.6";
  const result = await makeUpstreamRequest(token, body.messages, model);
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

  return new Response("Not Found", { status: 404 });
});
