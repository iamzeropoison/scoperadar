// ai.js: ScopeRadar's on-device AI helper
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)
//
// Uses Chrome's BUILT-IN on-device model (Gemini Nano via the Prompt API).
// No API key, no account, no external server, no cost. The model runs
// locally on the researcher's machine. This is genuinely free, unlike a
// "free tier" that still requires signing up for a key.
//
// Availability depends on the browser: Chrome 131+ desktop, with the
// on-device model downloaded (Chrome handles this automatically the first
// time a page asks for it, similar to a spellcheck-dictionary download).
// On unsupported browsers, callers get a clear status back instead of a
// broken feature.
//
// Scope: this assistant only helps with WRITING, polishing outreach
// emails and structuring vulnerability reports. It never invents technical
// details, and never produces exploit code or attack instructions.

'use strict';

const SCOPERADAR_AI_SYSTEM_PROMPT = `You are a writing assistant built into ScopeRadar, a tool for ethical bug bounty researchers practicing responsible disclosure.

You help with exactly two things:
1. Polishing permission-request / outreach emails to companies, making them professional, concise, and polite.
2. Structuring and clarifying vulnerability report drafts (description, steps to reproduce, impact, suggested fix) based on notes the researcher already wrote themselves.

Rules:
- Never invent technical details, vulnerabilities, or steps the researcher didn't already provide.
- Never produce exploit code, attack payloads, or instructions for compromising a system the researcher has not confirmed permission for.
- If asked for anything outside writing/editing help, politely decline and suggest focusing on clear report writing instead.
- Keep responses plain text, no markdown headers, ready to paste directly into an email or report field.`;

/** Which flavor of the on-device API this browser exposes, if any. */
function scopehoundAIBackend() {
  if (typeof LanguageModel !== 'undefined') return 'modern'; // Chrome 131+
  if (typeof self !== 'undefined' && self.ai && self.ai.languageModel) return 'legacy'; // Chrome 127-130 (flag-gated)
  return null;
}

/**
 * Checks whether the on-device model is ready to use.
 * @returns {Promise<{state: 'available'|'downloadable'|'downloading'|'unavailable'|'unsupported', label: string}>}
 */
async function scopehoundAIStatus() {
  const backend = scopehoundAIBackend();
  if (!backend) {
    return { state: 'unsupported', label: "This browser doesn't support on-device AI yet (needs Chrome 131+ on desktop)." };
  }
  try {
    if (backend === 'modern') {
      const avail = await LanguageModel.availability();
      const map = {
        available: { state: 'available', label: 'On-device AI is ready.' },
        downloadable: { state: 'downloadable', label: 'On-device AI model needs a one-time download (~a couple GB). Click to start it.' },
        downloading: { state: 'downloading', label: 'On-device AI model is downloading. Try again shortly.' },
        unavailable: { state: 'unavailable', label: "This device can't run the on-device model (hardware/storage requirements not met)." },
      };
      return map[avail] || { state: 'unavailable', label: `Unknown status: ${avail}` };
    }
    // legacy shape
    const caps = await self.ai.languageModel.capabilities();
    if (caps.available === 'readily') return { state: 'available', label: 'On-device AI is ready.' };
    if (caps.available === 'after-download') return { state: 'downloadable', label: 'On-device AI model needs a one-time download. Click to start it.' };
    return { state: 'unavailable', label: "This device can't run the on-device model." };
  } catch (err) {
    return { state: 'unsupported', label: err.message || 'Could not check AI availability.' };
  }
}

/** Triggers the model download (Chrome shows its own progress UI/notification). */
async function scopehoundAIDownload() {
  const backend = scopehoundAIBackend();
  try {
    if (backend === 'modern') {
      const session = await LanguageModel.create({
        expectedOutputs: [{ type: 'text', languages: ['en'] }],
        monitor(m) { m.addEventListener('downloadprogress', () => {}); },
      });
      session.destroy && session.destroy();
      return { ok: true };
    }
    if (backend === 'legacy') {
      const session = await self.ai.languageModel.create();
      session.destroy && session.destroy();
      return { ok: true };
    }
    return { ok: false, error: 'unsupported' };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Runs one prompt through the on-device model. Creates and destroys a
 * session per call (simple and safe for occasional "polish this" use).
 * @param {string} userPrompt
 * @returns {Promise<{text?: string, error?: string}>}
 */
async function scopehoundCallAI(userPrompt) {
  const session = await scopehoundCreateSession(SCOPERADAR_AI_SYSTEM_PROMPT);
  if (session.error) return { error: session.error };
  try {
    const text = await session.prompt(userPrompt);
    if (!text) return { error: 'Empty response from the on-device model. Try again.' };
    return { text };
  } catch (err) {
    return { error: err.message || 'On-device AI request failed.' };
  } finally {
    session.destroy();
  }
}

/**
 * Opens a multi-turn chat session with the on-device model. The returned
 * session keeps conversation context between calls to .prompt(), so this
 * is what the AI Assistant chat tab uses to let a researcher ask follow-up
 * questions, not just one-shot polishing.
 * @param {string} systemPrompt
 * @returns {Promise<{prompt?: (msg:string)=>Promise<string>, destroy?: ()=>void, error?: string}>}
 */
async function scopehoundCreateSession(systemPrompt) {
  const backend = scopehoundAIBackend();
  if (!backend) return { error: 'On-device AI is not supported in this browser (needs Chrome 131+).' };
  try {
    let raw;
    if (backend === 'modern') {
      raw = await LanguageModel.create({
        initialPrompts: systemPrompt ? [{ role: 'system', content: systemPrompt }] : [],
        // Chrome's Prompt API requires declaring the expected output
        // language explicitly (it uses this for output-safety attestation).
        // All of ScopeRadar's prompts/replies are in English.
        expectedOutputs: [{ type: 'text', languages: ['en'] }],
      });
    } else {
      raw = await self.ai.languageModel.create(systemPrompt ? { systemPrompt } : {});
    }
    return {
      prompt: async (msg) => (await raw.prompt(msg) || '').trim(),
      destroy: () => { if (raw && raw.destroy) { try { raw.destroy(); } catch {} } },
    };
  } catch (err) {
    return { error: err.message || 'Failed to start an on-device AI session.' };
  }
}

/** General-purpose system prompt for the open-ended AI Assistant chat tab. */
const SCOPERADAR_CHAT_SYSTEM_PROMPT = `You are the AI Assistant inside ScopeRadar, built for the researcher using it day to day. Answer whatever they ask, as completely and specifically as you can. Typical topics include vulnerability classes and CWE categories, CVSS scoring, writing up a finding, reading a program's scope or policy, drafting outreach emails, and general security or development questions, but you are not limited to that list. If something is outside security entirely, still just answer it helpfully.

Answer quality matters more than brevity. For each question:
- Give a direct, specific answer first, not a vague overview.
- When relevant, name the actual CWE ID, CVSS factors, or report section it maps to.
- Use a short concrete example when it makes the point clearer (a realistic scenario, not a real company).
- If a question is ambiguous, state the most likely reading and answer that, then briefly note what would change your answer.
- If something has nuance or exceptions, say so in a sentence instead of oversimplifying.
- When listing multiple points, number them plainly (1, 2, 3) rather than using markdown bullets or headers, since this is plain text, not a rendered document.
- Keep the whole answer tight. Favor a well-chosen couple of paragraphs over padding.

The one boundary: don't write exploit code or step-by-step intrusion instructions aimed at a specific system the researcher hasn't confirmed they're authorized to test. If that comes up, say so in one line and suggest confirming permission first, then keep helping with everything else in the question. Don't extend this caution to topics where it doesn't apply.`;

// Explicitly exposed (not just relying on classic-script global scope
// sharing) so options.js can reference it reliably.
if (typeof self !== 'undefined') self.SCOPERADAR_CHAT_SYSTEM_PROMPT = SCOPERADAR_CHAT_SYSTEM_PROMPT;
