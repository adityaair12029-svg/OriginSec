import dns from 'node:dns/promises';
import net from 'node:net';

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  hostname?: string;
  port?: number;
  protocol?: 'http:' | 'https:';
  error?: string;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  '169.254.169.254',
  '100.100.100.200',
  '0.0.0.0',
]);

const BLOCKED_SUFFIXES = ['.local', '.internal', '.localhost', '.arpa', '.lan', '.home', '.corp'];

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return -1;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr4(ipInt: number, baseStr: string, maskBits: number): boolean {
  const baseInt = ipv4ToInt(baseStr);
  if (baseInt === -1 || ipInt === -1) return true;
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to a private, loopback,
 * link-local, multicast, CGNAT, cloud metadata, or otherwise reserved non-public range.
 */
export function isPrivateOrReservedIp(ipRaw: string): boolean {
  const ip = ipRaw.trim().toLowerCase();
  if (!ip) return true;

  // Strip IPv6 zone index if present (e.g. fe80::1%eth0)
  const zoneClean = ip.split('%')[0];

  if (net.isIPv4(zoneClean)) {
    const ipInt = ipv4ToInt(zoneClean);
    if (ipInt === -1) return true;

    const blockedRanges: Array<[string, number]> = [
      ['0.0.0.0', 8],       // "This" network
      ['10.0.0.0', 8],      // Private RFC 1918
      ['100.64.0.0', 10],   // Carrier-grade NAT RFC 6598
      ['127.0.0.0', 8],     // Loopback
      ['169.254.0.0', 16],  // Link-local & AWS/GCP/Azure metadata (169.254.169.254)
      ['172.16.0.0', 12],   // Private RFC 1918
      ['192.0.0.0', 24],    // IETF Protocol Assignments
      ['192.0.2.0', 24],    // TEST-NET-1
      ['192.88.99.0', 24],  // 6to4 Relay Anycast
      ['192.168.0.0', 16],  // Private RFC 1918
      ['198.18.0.0', 15],   // Network benchmark
      ['198.51.100.0', 24], // TEST-NET-2
      ['203.0.113.0', 24],  // TEST-NET-3
      ['224.0.0.0', 4],     // Multicast
      ['240.0.0.0', 4],     // Reserved / Broadcast
    ];

    return blockedRanges.some(([base, bits]) => inCidr4(ipInt, base, bits));
  }

  if (net.isIPv6(zoneClean)) {
    // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (zoneClean.startsWith('::ffff:')) {
      const mapped = zoneClean.slice(7);
      if (net.isIPv4(mapped)) {
        return isPrivateOrReservedIp(mapped);
      }
      // Hex form like ::ffff:7f00:0001
      const hexParts = mapped.split(':');
      if (hexParts.length === 2) {
        const hi = parseInt(hexParts[0], 16);
        const lo = parseInt(hexParts[1], 16);
        if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
          const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
          return isPrivateOrReservedIp(ipv4);
        }
      }
      return true;
    }

    if (zoneClean === '::' || zoneClean === '::1') return true;
    if (zoneClean.startsWith('fc') || zoneClean.startsWith('fd')) return true; // Unique local fc00::/7
    if (zoneClean.startsWith('fe8') || zoneClean.startsWith('fe9') || zoneClean.startsWith('fea') || zoneClean.startsWith('feb')) return true; // Link-local fe80::/10
    if (zoneClean.startsWith('ff')) return true; // Multicast ff00::/8
    if (zoneClean.startsWith('100::')) return true; // Discard prefix
    if (zoneClean.startsWith('2001:db8:')) return true; // Documentation
    if (zoneClean.startsWith('2001:0:')) return true; // Teredo
    if (zoneClean.startsWith('2002:')) return true; // 6to4

    return false;
  }

  return true;
}

/**
 * Validates and normalizes an incoming target URL before any network resolution.
 * Rejects non-HTTP(S), embedded credentials, non-standard ports, and private/reserved hosts.
 */
export function validateTargetUrl(rawInput: string): UrlValidationResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, error: 'Please enter a website URL to analyze.' };
  }

  if (trimmed.length > 2048) {
    return { valid: false, error: 'URL exceeds maximum allowed length (2048 characters).' };
  }

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Invalid URL format. Example: https://example.com' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Unsupported protocol "${parsed.protocol}". Only http:// and https:// targets are permitted.`,
    };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: 'URLs containing embedded credentials are not permitted.' };
  }

  const portStr = parsed.port;
  if (portStr) {
    const portNum = Number(portStr);
    const allowedPort = (parsed.protocol === 'http:' && portNum === 80) || (parsed.protocol === 'https:' && portNum === 443);
    if (!allowedPort) {
      return {
        valid: false,
        error: `Non-standard port :${portStr} is blocked. Public scans only permit standard ports 80 and 443.`,
      };
    }
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname.length > 253) {
    return { valid: false, error: 'Invalid or missing hostname.' };
  }

  if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_SUFFIXES.some((s) => hostname.endsWith(s))) {
    return { valid: false, error: 'Scanning localhost, internal domains, or metadata endpoints is blocked.' };
  }

  // Strip IPv6 brackets if literal
  const bareHost = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (net.isIP(bareHost)) {
    if (isPrivateOrReservedIp(bareHost)) {
      return { valid: false, error: 'Scanning private, loopback, link-local, or reserved IP addresses is blocked.' };
    }
  } else if (!hostname.includes('.')) {
    return { valid: false, error: 'Please provide a fully qualified public domain name (e.g. https://example.com).' };
  }

  // Normalize URL canonically: remove fragment, strip common tracking query parameters,
  // and sort remaining query parameters for deterministic cross-device scans.
  parsed.hash = '';
  const trackingPrefixes = ['utm_', 'fbclid', 'gclid', 'yclid', 'mc_cid', 'mc_eid', 'msclkid'];
  const keptParams: Array<[string, string]> = [];
  parsed.searchParams.forEach((value, key) => {
    const lk = key.toLowerCase();
    if (!trackingPrefixes.some((p) => lk === p || lk.startsWith(p))) {
      keptParams.push([key, value]);
    }
  });
  keptParams.sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));
  parsed.search = '';
  for (const [k, v] of keptParams) {
    parsed.searchParams.append(k, v);
  }

  const port = parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    hostname: bareHost,
    port,
    protocol: parsed.protocol,
  };
}

export interface VerifiedResolution {
  safe: boolean;
  addresses: string[];
  primaryAddress?: string;
  error?: string;
}

/**
 * Resolves DNS for a hostname and checks every returned IPv4/IPv6 address against
 * the SSRF blocklist. Called before initial connection and on every redirect hop.
 */
export async function resolveAndVerifyHost(hostname: string): Promise<VerifiedResolution> {
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      return { safe: false, addresses: [], error: `Target IP ${hostname} is private or reserved.` };
    }
    return { safe: true, addresses: [hostname], primaryAddress: hostname };
  }

  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    if (!records || records.length === 0) {
      return { safe: false, addresses: [], error: `DNS lookup returned no addresses for ${hostname}.` };
    }

    const addresses = Array.from(new Set(records.map((r) => r.address))).sort();
    for (const addr of addresses) {
      if (isPrivateOrReservedIp(addr)) {
        return {
          safe: false,
          addresses,
          error: `SSRF protection blocked ${hostname}: resolved to non-public IP address ${addr}.`,
        };
      }
    }

    return {
      safe: true,
      addresses,
      primaryAddress: addresses[0],
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { safe: false, addresses: [], error: `DNS resolution failed for ${hostname}: ${msg}` };
  }
}
