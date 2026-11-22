import type { WebsiteScan } from '../../types/audit';

export interface ScoreTrendPoint {
  scanId: string;
  label: string;
  fullDate: string;
  domain: string;
  security: number;
  overall: number;
  frontend: number;
  backend: number;
  engagement: number;
}

export interface WebsiteTrendSummary {
  domain: string;
  points: ScoreTrendPoint[];
  securityDelta: number | null;
  overallDelta: number | null;
  latestSecurity: number | null;
  latestOverall: number | null;
}

/**
 * Computes chronological score trend series over the last `limit` (default 5)
 * completed/partially_completed scans for a specific website domain (or across all websites).
 */
export function buildWebsiteScoreTrends(
  scans: WebsiteScan[],
  selectedDomain: string,
  limit = 5
): WebsiteTrendSummary {
  const completed = scans.filter(
    (s) =>
      (s.status === 'completed' || s.status === 'partially_completed') &&
      (selectedDomain === 'all' || s.normalizedDomain === selectedDomain)
  );

  // Sort chronologically oldest -> newest after taking the latest `limit` scans
  const latestSubset = [...completed]
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, limit)
    .reverse();

  const points: ScoreTrendPoint[] = latestSubset.map((s, idx) => {
    const dt = new Date(s.startedAt);
    const shortDate = Number.isNaN(dt.getTime())
      ? `Scan ${idx + 1}`
      : dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return {
      scanId: s.scanId,
      label: `#${idx + 1} · ${shortDate}`,
      fullDate: Number.isNaN(dt.getTime()) ? s.startedAt : dt.toLocaleString(),
      domain: s.normalizedDomain,
      security: s.scores?.security ?? 0,
      overall: s.scores?.overall ?? 0,
      frontend: s.scores?.frontend ?? 0,
      backend: s.scores?.backend ?? 0,
      engagement: s.scores?.engagement ?? 0,
    };
  });

  const latest = points[points.length - 1] ?? null;
  const previous = points.length >= 2 ? points[points.length - 2] : null;

  return {
    domain: selectedDomain,
    points,
    securityDelta: latest && previous ? latest.security - previous.security : null,
    overallDelta: latest && previous ? latest.overall - previous.overall : null,
    latestSecurity: latest ? latest.security : null,
    latestOverall: latest ? latest.overall : null,
  };
}
