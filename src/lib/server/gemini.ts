import { GoogleGenAI } from '@google/genai';
import type { WebsiteScan } from '../../types/audit';

export function isGeminiConfigured(): boolean {
  const key = process.env.GEMINI_API_KEY;
  return Boolean(key && key !== 'MY_GEMINI_API_KEY' && key.trim().length > 10);
}

/**
 * Generates an understandable, evidence-grounded explanation of verified scan findings
 * for developers and website owners using Gemini (@google/genai).
 * Strictly strips any sensitive tokens/headers and never fabricates scan results.
 */
export async function explainScanFindingsWithGemini(params: {
  scan: Pick<WebsiteScan, 'normalizedDomain' | 'targetUrl' | 'scores' | 'coverage' | 'metrics' | 'findings'>;
  audience: 'owner' | 'developer';
}): Promise<{ available: boolean; explanation?: string; error?: string }> {
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

  // Pass strictly sanitized deterministic evidence (no cookies, secrets, or tokens)
  const sanitizedFindings = (params.scan.findings || [])
    .filter((f) => f.severity !== 'passed')
    .slice(0, 18)
    .map((f) => ({
      category: f.category,
      title: f.title,
      severity: f.severity,
      observedValue: f.observedValue,
      evidence: f.evidence,
      status: f.status,
    }));

  const sanitizedContext = {
    domain: params.scan.normalizedDomain,
    targetUrl: params.scan.targetUrl,
    scores: params.scan.scores,
    coverage: params.scan.coverage,
    metrics: {
      ttfbMs: params.scan.metrics?.ttfbMs,
      totalResponseTimeMs: params.scan.metrics?.totalResponseTimeMs,
      statusCode: params.scan.metrics?.statusCode,
      domNodeCount: params.scan.metrics?.domNodeCount,
      tlsProtocol: params.scan.metrics?.tls?.protocol,
      tlsDaysRemaining: params.scan.metrics?.tls?.daysRemaining,
    },
    findings: sanitizedFindings,
  };

  const audienceInstruction =
    params.audience === 'developer'
      ? 'Write a concise, actionable technical remediation brief for a full-stack/DevOps engineer. Include exact priority order (Fix Immediately, Fix Soon, Optimizations) and concrete server/header/HTML guidance.'
      : 'Write a clear, non-jargon executive briefing for a website owner explaining what the observed findings mean for visitor trust, security, and speed, and which 3 priorities to tackle first.';

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: `Analyze ONLY the following verified OriginSec scan evidence for ${sanitizedContext.domain}. Do NOT invent any vulnerabilities, scores, or checks that are not present in this JSON. Explicitly note when database/hosting/backup checks were not assessed due to missing integrations.\n\nEvidence JSON:\n${JSON.stringify(sanitizedContext, null, 2)}`,
      config: {
        systemInstruction: `You are an objective cybersecurity and web quality analyst for OriginSec. ${audienceInstruction} Label your output clearly as an AI-generated interpretation of verified deterministic scan evidence. Keep response under 450 words.`,
      },
    });

    const text = response.text?.trim();
    if (!text) {
      return { available: true, error: 'Model returned an empty response.' };
    }

    return { available: true, explanation: text };
  } catch (err) {
    return {
      available: true,
      error: err instanceof Error ? err.message : 'Failed to generate AI explanation.',
    };
  }
}
