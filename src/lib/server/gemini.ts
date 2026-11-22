import { GoogleGenAI } from '@google/genai';
import type { GroundingSource, WebsiteScan } from '../../types/audit';

export function isGeminiConfigured(): boolean {
  const key = process.env.GEMINI_API_KEY;
  return Boolean(key && key !== 'MY_GEMINI_API_KEY' && key.trim().length > 10);
}

/**
 * Extracts verified HTTP/HTTPS grounding sources from Gemini googleSearch groundingChunks.
 */
export function extractGroundingSources(chunks: unknown): GroundingSource[] {
  if (!Array.isArray(chunks)) return [];
  const seen = new Set<string>();
  const sources: GroundingSource[] = [];

  for (const chunk of chunks) {
    if (!chunk || typeof chunk !== 'object') continue;
    const web = (chunk as { web?: { uri?: unknown; title?: unknown } }).web;
    if (!web || typeof web.uri !== 'string') continue;

    try {
      const parsed = new URL(web.uri);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      const cleanUri = parsed.toString();
      if (seen.has(cleanUri)) continue;
      seen.add(cleanUri);
      sources.push({
        title: typeof web.title === 'string' && web.title.trim() ? web.title.trim() : parsed.hostname,
        uri: cleanUri,
      });
    } catch {
      // Ignore malformed URIs
    }
    if (sources.length >= 8) break;
  }

  return sources;
}

function buildSanitizedScanContext(
  scan: Pick<WebsiteScan, 'normalizedDomain' | 'targetUrl' | 'scores' | 'coverage' | 'metrics' | 'findings'>
) {
  const sanitizedFindings = (scan.findings || [])
    .filter((f) => f.severity !== 'passed')
    .slice(0, 22)
    .map((f) => ({
      ruleId: f.ruleId,
      category: f.category,
      subCategory: f.subCategory,
      title: f.title,
      severity: f.severity,
      observedValue: f.observedValue,
      evidence: f.evidence,
      status: f.status,
    }));

  return {
    domain: scan.normalizedDomain,
    targetUrl: scan.targetUrl,
    scores: scan.scores,
    coverage: scan.coverage,
    metrics: {
      ttfbMs: scan.metrics?.ttfbMs,
      totalResponseTimeMs: scan.metrics?.totalResponseTimeMs,
      statusCode: scan.metrics?.statusCode,
      domNodeCount: scan.metrics?.domNodeCount,
      tlsProtocol: scan.metrics?.tls?.protocol,
      tlsDaysRemaining: scan.metrics?.tls?.daysRemaining,
    },
    findings: sanitizedFindings,
  };
}

/**
 * Generates an evidence-grounded explanation of verified scan findings with Gemini 4 + Google Search Grounding.
 * Strictly strips any sensitive tokens/headers and never fabricates scan results.
 */
export async function explainScanFindingsWithGemini(params: {
  scan: Pick<WebsiteScan, 'normalizedDomain' | 'targetUrl' | 'scores' | 'coverage' | 'metrics' | 'findings'>;
  audience: 'owner' | 'developer';
}): Promise<{ available: boolean; explanation?: string; sources?: GroundingSource[]; error?: string }> {
  if (!isGeminiConfigured()) {
    return {
      available: false,
      error: 'GEMINI_API_KEY is not configured on the server. AI explanations are unavailable; all deterministic scan findings remain accessible.',
    };
  }

  const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const sanitizedContext = buildSanitizedScanContext(params.scan);
  const audienceInstruction =
    params.audience === 'developer'
      ? 'Write a concise, actionable technical remediation brief for a full-stack/DevOps engineer. Include exact priority order (Fix Immediately, Fix Soon, Optimizations), concrete server/header/HTML guidance, and reference current OWASP/MDN standards via Google Search where helpful.'
      : 'Write a clear, non-jargon executive briefing for a website owner explaining what the observed findings mean for visitor trust, security, and speed, and which 3 priorities to tackle first.';

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: `Analyze ONLY the following verified OriginSec scan evidence for ${sanitizedContext.domain}. Do NOT invent any vulnerabilities, scores, or checks that are not present in this JSON. Explicitly note when database/hosting/backup checks were not assessed due to missing integrations.\n\nEvidence JSON:\n${JSON.stringify(sanitizedContext, null, 2)}`,
      config: {
        systemInstruction: `You are an objective cybersecurity and web quality analyst for OriginSec. ${audienceInstruction} Label your output clearly as an AI-generated interpretation of verified deterministic scan evidence. Keep response under 450 words.`,
        tools: [{ googleSearch: {} }],
      },
    });

    const text = response.text?.trim();
    if (!text) {
      return { available: true, error: 'Model returned an empty response.' };
    }

    const sources = extractGroundingSources(response.candidates?.[0]?.groundingMetadata?.groundingChunks);
    return { available: true, explanation: text, sources };
  } catch (err) {
    return {
      available: true,
      error: err instanceof Error ? err.message : 'Failed to generate AI explanation.',
    };
  }
}

export async function askAiAboutScanWithGemini(params: {
  scan: Pick<WebsiteScan, 'normalizedDomain' | 'targetUrl' | 'scores' | 'coverage' | 'metrics' | 'findings'>;
  question: string;
}): Promise<{ available: boolean; answer?: string; sources?: GroundingSource[]; error?: string }> {
  if (!isGeminiConfigured()) {
    return {
      available: false,
      error: 'GEMINI_API_KEY is not configured on the server.',
    };
  }

  const ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const sanitizedContext = buildSanitizedScanContext(params.scan);
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: `User question: ${params.question}\n\nVerified OriginSec Evidence JSON for ${sanitizedContext.domain}:\n${JSON.stringify(sanitizedContext, null, 2)}`,
      config: {
        systemInstruction:
          'You are ORIGINSEC AI ANALYST. Answer the user question grounded in the verified facts from the supplied OriginSec scan evidence JSON, and use Google Search grounding when referencing up-to-date security standards (OWASP, MDN headers, TLS/HSTS preload rules, or WCAG criteria). Never invent vulnerabilities, database state, or hidden endpoints on the target site. If something was not assessed or is unavailable, state that explicitly. Keep answers concise (<= 260 words).',
        tools: [{ googleSearch: {} }],
      },
    });
    const text = response.text?.trim();
    if (!text) {
      return { available: true, error: 'Model returned an empty answer.' };
    }
    const sources = extractGroundingSources(response.candidates?.[0]?.groundingMetadata?.groundingChunks);
    return { available: true, answer: text, sources };
  } catch (err) {
    return {
      available: true,
      error: err instanceof Error ? err.message : 'Failed to answer question.',
    };
  }
}
