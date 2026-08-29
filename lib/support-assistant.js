"use strict";

const TRANSFER_PATTERN = /\b(human|person|representative|live agent|support agent|staff member|transfer me|talk to (?:someone|support))\b/i;

function redactSupportSecrets(value) {
  return String(value || "")
      .replace(/\bSHARE(?:-[A-Z0-9_]{4}){3,}\b/gi, "[browser token removed]")
      .replace(/\b(?:RCVY|RECOVERY)(?:-[A-Z0-9]{4}){2,}\b/gi, "[recovery code removed]")
      .replace(/\b[A-Z0-9]{5}-[A-Z0-9]{5}\b/g, "[connection code removed]")
      .replace(/\b(pin|password)\s*(?:is|:)?\s*\d{4,8}\b/gi, "$1 [removed]");
}

function includesAny(text, expressions) {
  return expressions.some((expression) => expression.test(text));
}

function latestDiagnostic(diagnostics, events) {
  return diagnostics.find((item) => events.includes(String(item.event || "").toUpperCase()));
}

const KNOWLEDGE_STOP_WORDS = new Set([
  "about", "after", "again", "also", "because", "browser", "could", "does",
  "from", "have", "help", "into", "just", "like", "please", "scriptnovaa",
  "should", "that", "their", "there", "these", "they", "this", "what",
  "when", "where", "which", "with", "would", "your",
]);

function suggestKnowledgeKeywords(value) {
  return [...new Set(String(value || "").toLowerCase()
      .replace(/[^a-z0-9\s-]/g, " ")
      .split(/\s+/)
      .filter((word) => word.length >= 4 && !KNOWLEDGE_STOP_WORDS.has(word)))]
      .slice(0, 10);
}

function matchingKnowledge(text, entries) {
  let best = null;
  for (const entry of entries || []) {
    if (entry.active !== true || !Array.isArray(entry.keywords)) continue;
    const matches = entry.keywords.filter((keyword) =>
      String(keyword || "").length >= 2 && text.includes(String(keyword).toLowerCase()));
    if (!matches.length) continue;
    const score = matches.reduce((total, keyword) => total + String(keyword).length, 0);
    if (!best || score > best.score) best = {entry, score};
  }
  return best?.entry || null;
}

function diagnosticSummary(diagnostic) {
  if (!diagnostic) return "";
  const browser = diagnostic.browser ? ` for ${diagnostic.browser}` : "";
  const detail = String(diagnostic.detail || "").trim();
  return `I found a recent ${String(diagnostic.event || "launcher event").replace(/_/g, " ").toLowerCase()}${browser}${detail ? `: ${detail}` : "."}`;
}

function supportAssistantReply(message, context = {}) {
  const text = String(message || "").trim();
  const normalized = text.toLowerCase();
  const priorText = (context.previousUserMessages || []).slice(-4).join(" ").toLowerCase();
  const conversationText = `${priorText} ${normalized}`.trim();
  const account = context.account || {};
  const diagnostics = Array.isArray(context.diagnostics) ? context.diagnostics : [];
  const status = String(account.accountStatus || "ACTIVE").toUpperCase();

  if (TRANSFER_PATTERN.test(normalized)) {
    return {
      transfer: true,
      message: "I’ll place this chat in the representative queue. You can keep adding useful details while you wait. Response times are not guaranteed, so use a support ticket for anything important.",
    };
  }

  if (includesAny(normalized, [/\bpin\b/, /recovery code/, /password/, /browser token/, /connection code/]) &&
      includesAny(normalized, [/send/, /share/, /tell you/, /give you/, /what is my/])) {
    return {transfer: false, message: "Please do not send your PIN, recovery code, browser token, or connection code. ScriptNovaa Support never needs those secrets. Tell me what the code is failing to do instead."};
  }

  if (includesAny(conversationText, [/\bban(?:ned)?\b/, /un ?ban/, /suspend(?:ed|sion)?/, /terminat(?:ed|ion)/, /restriction/, /appeal/])) {
    if (status === "ACTIVE") {
      return {transfer: false, message: "Your account currently shows as active and has no account restriction to appeal. If a page says otherwise, sign out, sign back in, and tell me the exact message you see."};
    }
    const rawReason = String(account.statusReason || "No public reason was recorded.");
    const reason = rawReason.length > 180 ? `${rawReason.slice(0, 177)}…` : rawReason;
    const end = Number(account.statusEndsAt || 0) > 0 ?
      `The scheduled end is ${new Date(Number(account.statusEndsAt)).toLocaleString("en-US", {timeZone: "America/New_York"})} Eastern Time.` :
      "There is no scheduled automatic end date; it remains in place unless an administrator changes it or approves an appeal.";
    return {transfer: false, message: `Your account is ${status.toLowerCase()}. Reason: ${reason}. ${end} You may submit an appeal from the restriction screen. Explain what happened, include relevant dates or diagnostic references, and do not include private codes. Only an administrator can change this status.`};
  }

  if (includesAny(normalized, [/nothing happens/, /(?:won'?t|will not) (?:open|launch|start)/, /(?:doesn'?t|does not) (?:open|launch|start)/, /launch(?:er|ing)?/, /browser closed/, /chrome/, /edge/])) {
    const failure = latestDiagnostic(diagnostics, ["START_FAILED", "BROWSER_CLOSED"]);
    const launched = latestDiagnostic(diagnostics, ["BROWSER_LAUNCHED"]);
    if (failure) {
      return {transfer: false, message: `${diagnosticSummary(failure)} Completely close Share Browser and reopen it, confirm you have the latest launcher, and try the other supported browser if available. If it fails again, ask for a representative and mention that this diagnostic was found.`};
    }
    if (launched) {
      return {transfer: false, message: `${diagnosticSummary(launched)} The API recorded a successful launch, so first completely close Share Browser and the selected browser, then reopen Share Browser and try again. If the window still does not appear, ask for a representative so the launch details can be reviewed.`};
    }
    return {transfer: false, message: "I could not find a recent launcher diagnostic for this account. Completely close Share Browser, reopen it, and try once more. If it still fails, leave the launcher open, return here immediately, and ask for a representative so the newest logs can be checked."};
  }

  if (includesAny(normalized, [/connect/, /pair/, /computer/, /device/])) {
    if (account.registeredDeviceId) {
      return {transfer: false, message: "Your account shows a registered computer. If the website still says “Not registered,” refresh the page, confirm you are signed into the same account, and avoid using two accounts in the same browser tab. If the launcher itself rejects the connection, ask for a representative."};
    }
    return {transfer: false, message: "Your account does not currently show a registered computer. Generate the one-time connection code from Tokens, open the newest Share Browser launcher, and enter it under One-time connection code. If a code was already used or expired, submit a connection-code replacement ticket."};
  }

  if (includesAny(normalized, [/refund/, /points? back/, /restore.*points?/, /lost points?/])) {
    return {transfer: false, message: "The assistant and live representatives cannot refund or restore points through chat. If your balance is incorrect because of a technical error, submit a Points or sponsored rewards ticket with the date, action, and error message. Do not include private codes. An administrator can review the account ledger, but a refund is not guaranteed."};
  }

  if (includesAny(normalized, [/token/, /points?/, /reward/, /sponsor/, /redirect/, /referral/])) {
    if (/referral/.test(normalized)) {
      return {transfer: false, message: "Referral rewards begin as pending and are released only after the referred account completes the required device, session, and safety checks. An incomplete referral loses only its pending reward; confirmed fraud may reverse rewards and add a penalty. A representative can review a specific referral, but live chat cannot restore points."};
    }
    if (/reward|sponsor|redirect/.test(normalized)) {
      return {transfer: false, message: "Sponsored rewards must be opened from the signed-in Tokens page and claimed from that same account after the displayed timer. Ad blocking can prevent the reward from counting. Refresh the reward status before retrying; do not repeatedly submit the same claim. Live chat cannot refund or restore points."};
    }
    return {transfer: false, message: `Your account currently shows ${Number(account.pointBalance || 0)} available points and ${Number(account.pendingPointBalance || 0)} pending points. Browser tokens are single-session and cannot be paused or reused after a completed session. If a token failed during launch, tell me the exact message and selected browser.`};
  }

  if (includesAny(normalized, [/sign in/, /login/, /account access/, /forgot/, /recover/])) {
    return {transfer: false, message: "For sign-in problems, verify the username and 4–8 digit PIN, then wait before retrying if rate limited. If you forgot the PIN, use the saved recovery code on the recovery page. Never send that recovery code in chat. Without the PIN and recovery code, support cannot prove ownership automatically."};
  }

  if (includesAny(normalized, [/developer program/, /beta program/, /embed/, /own browser/])) {
    return {transfer: false, message: "The ScriptNova Developer Program is in beta. Use a Developer Program support ticket for applications, partnership details, or domain embedding. Include what you want to build, your audience, and how you plan to follow ScriptNovaa’s safety and platform rules."};
  }

  const learned = matchingKnowledge(conversationText, context.knowledge);
  if (learned) {
    return {transfer: false, message: `From the approved ScriptNovaa support guide: ${String(learned.answer || "").slice(0, 800)}`};
  }

  if (normalized.split(/\s+/).length <= 4) {
    return {transfer: false, message: "I’m here for ScriptNovaa and Share Browser support, and I may need a little more context. Tell me what happened, what you clicked, and what you expected. You can also ask for a representative at any time."};
  }

  return {transfer: false, message: "I can help with Share Browser launching, computer connection, tokens, sponsored rewards, referrals, sign-in, account restrictions, appeals, and the Developer Program. Tell me what you clicked, what you expected, and the exact message you saw. You can ask for a representative at any time."};
}

module.exports = {
  supportAssistantReply,
  redactSupportSecrets,
  suggestKnowledgeKeywords,
  TRANSFER_PATTERN,
};
