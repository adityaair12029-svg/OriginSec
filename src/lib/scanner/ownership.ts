import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import * as cheerio from 'cheerio';
import { safeFetchText } from './engine';
import { resolveAndVerifyHost, validateTargetUrl } from './ssrf';

export function generateVerificationChallenge(domain: string): {
  normalizedDomain: string;
  challengeToken: string;
  dnsTxtName: string;
  dnsTxtValue: string;
  htmlMetaTag: string;
  wellKnownUrl: string;
} {
  const validated = validateTargetUrl(domain);
  const normalizedDomain = validated.hostname || domain.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  const challengeToken = `originsec-verify=${crypto.randomBytes(16).toString('hex')}`;

  return {
    normalizedDomain,
    challengeToken,
    dnsTxtName: `_originsec.${normalizedDomain}`,
    dnsTxtValue: challengeToken,
    htmlMetaTag: `<meta name="originsec-verification" content="${challengeToken}" />`,
    wellKnownUrl: `https://${normalizedDomain}/.well-known/originsec-verification.txt`,
  };
}

export async function verifyDomainOwnership(params: {
  domain: string;
  method: 'dns_txt' | 'html_meta' | 'well_known';
  challengeToken: string;
}): Promise<{ verified: boolean; evidence: string }> {
  const validated = validateTargetUrl(`https://${params.domain}`);
  if (!validated.valid || !validated.hostname) {
    return { verified: false, evidence: validated.error || 'Invalid domain name.' };
  }

  const host = validated.hostname;
  const resolved = await resolveAndVerifyHost(host);
  if (!resolved.safe) {
    return { verified: false, evidence: resolved.error || 'Domain resolved to non-public address.' };
  }

  if (params.method === 'dns_txt') {
    try {
      const [subTxt, rootTxt] = await Promise.allSettled([
        dns.resolveTxt(`_originsec.${host}`),
        dns.resolveTxt(host),
      ]);
      const allRecords: string[] = [];
      if (subTxt.status === 'fulfilled') allRecords.push(...subTxt.value.map((p) => p.join('')));
      if (rootTxt.status === 'fulfilled') allRecords.push(...rootTxt.value.map((p) => p.join('')));

      if (allRecords.some((r) => r.includes(params.challengeToken))) {
        return {
          verified: true,
          evidence: `Verified DNS TXT record containing ${params.challengeToken} on ${host}.`,
        };
      }
      return {
        verified: false,
        evidence: `DNS TXT lookup for _originsec.${host} and ${host} found ${allRecords.length} record(s), none matching token.`,
      };
    } catch (err) {
      return {
        verified: false,
        evidence: `DNS TXT verification failed: ${err instanceof Error ? err.message : 'lookup error'}`,
      };
    }
  }

  if (params.method === 'html_meta') {
    const res = await safeFetchText(`https://${host}/`, { timeoutMs: 6000, maxBytes: 512 * 1024 });
    if (!res.ok) {
      return { verified: false, evidence: `Could not fetch homepage HTML: ${res.error || `HTTP ${res.statusCode}`}` };
    }
    const $ = cheerio.load(res.body);
    const metaContent = $('meta[name="originsec-verification"]').attr('content')?.trim();
    if (metaContent === params.challengeToken) {
      return {
        verified: true,
        evidence: `Verified <meta name="originsec-verification"> tag on ${res.finalUrl}.`,
      };
    }
    return {
      verified: false,
      evidence: `Homepage HTML did not contain matching originsec-verification meta tag (observed: ${metaContent || 'none'}).`,
    };
  }

  // well_known
  const wkUrl = `https://${host}/.well-known/originsec-verification.txt`;
  const wkRes = await safeFetchText(wkUrl, { timeoutMs: 6000, maxBytes: 16384 });
  if (wkRes.ok && wkRes.statusCode === 200 && wkRes.body.includes(params.challengeToken)) {
    return {
      verified: true,
      evidence: `Verified token in ${wkUrl}.`,
    };
  }
  return {
    verified: false,
    evidence: `Verification file ${wkUrl} returned HTTP ${wkRes.statusCode || 0} without matching token.`,
  };
}
