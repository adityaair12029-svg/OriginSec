import { jsPDF } from 'jspdf';
import type { WebsiteScan } from '../../types/audit';

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportScanAsJson(scan: WebsiteScan) {
  const payload = {
    schemaVersion: 'originsec-report-v2',
    exportedAt: new Date().toISOString(),
    generator: 'OriginSec 2.0 by DopTails (Founder: Aditya Choudhary)',
    assessmentScope: {
      scanProfile: scan.scanProfile || scan.coverage?.scanProfile || 'standard',
      authorizedConfirmed: scan.authorizedConfirmed,
      postureFingerprint: scan.postureFingerprint || null,
      pagesScanned: scan.coverage?.pagesScanned ?? 1,
    },
    methodology:
      'External passive & safe HTTP/TLS/DNS/HTML inspection. Unconnected infrastructure, database, and backup categories are explicitly marked Not assessed.',
    report: {
      scanId: scan.scanId,
      targetUrl: scan.targetUrl,
      normalizedDomain: scan.normalizedDomain,
      status: scan.status,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      coverage: scan.coverage,
      scores: scan.scores,
      summary: scan.summary,
      aiExplanation: scan.aiExplanation || null,
      metrics: scan.metrics,
      findingsCount: scan.findingsCount,
      findings: scan.findings || [],
    },
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
  triggerDownload(blob, `originsec-report-${scan.normalizedDomain}-${scan.scanId}.json`);
}

function escapeCsvCell(val: string | number | null | undefined): string {
  const str = val === null || val === undefined ? '' : String(val);
  const safe = str.replace(/"/g, '""');
  return `"${safe}"`;
}

export function exportScanAsCsv(scan: WebsiteScan) {
  const headers = [
    'Finding ID',
    'Rule ID',
    'Category',
    'SubCategory',
    'Title',
    'Severity',
    'Priority',
    'Status',
    'Confidence',
    'Affected URL',
    'Observed Value',
    'Description',
    'Evidence',
    'Impact',
    'Recommendation',
    'Remediation Example',
    'Verification',
    'Detected At',
  ];

  const rows = (scan.findings || []).map((f) =>
    [
      f.findingId,
      f.ruleId || '',
      f.category,
      f.subCategory || '',
      f.title,
      f.severity.toUpperCase(),
      f.priorityGroup,
      f.status,
      f.confidence || '',
      f.affectedUrl,
      f.observedValue,
      f.description,
      f.evidence,
      f.impact,
      f.recommendation,
      f.remediation,
      f.verification,
      f.createdAt,
    ]
      .map(escapeCsvCell)
      .join(',')
  );

  const csvContent = [headers.map(escapeCsvCell).join(','), ...rows].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
  triggerDownload(blob, `originsec-findings-${scan.normalizedDomain}-${scan.scanId}.csv`);
}

export function buildScanHistoryCsvContent(scans: WebsiteScan[]): string {
  const headers = [
    'Scan ID',
    'Domain',
    'Target URL',
    'Scan Profile',
    'Status',
    'Posture Fingerprint',
    'Overall Score',
    'Security Score',
    'Front-End Score',
    'Back-End Score',
    'Engagement Score',
    'SEO Score',
    'Accessibility Score',
    'Performance Score',
    'Critical Issues',
    'High Issues',
    'Medium Issues',
    'Low Issues',
    'Passed Checks',
    'Pages Scanned',
    'TTFB (ms)',
    'Started At',
    'Completed At',
  ];

  const rows = scans.map((s) =>
    [
      s.scanId,
      s.normalizedDomain,
      s.targetUrl,
      s.scanProfile || s.coverage?.scanProfile || 'standard',
      s.status,
      s.postureFingerprint || '',
      s.scores?.overall ?? '',
      s.scores?.security ?? '',
      s.scores?.frontend ?? '',
      s.scores?.backend ?? '',
      s.scores?.engagement ?? '',
      s.scores?.seo ?? '',
      s.scores?.accessibility ?? '',
      s.scores?.performance ?? '',
      s.findingsCount?.critical ?? 0,
      s.findingsCount?.high ?? 0,
      s.findingsCount?.medium ?? 0,
      s.findingsCount?.low ?? 0,
      s.findingsCount?.passed ?? 0,
      s.coverage?.pagesScanned ?? 1,
      s.metrics?.ttfbMs ?? '',
      s.startedAt,
      s.completedAt || '',
    ]
      .map(escapeCsvCell)
      .join(',')
  );

  return [headers.map(escapeCsvCell).join(','), ...rows].join('\r\n');
}

export function exportScanHistoryAsCsv(scans: WebsiteScan[]) {
  const csvContent = buildScanHistoryCsvContent(scans);
  const stamp = new Date().toISOString().slice(0, 10);
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
  triggerDownload(blob, `originsec-scan-history-${stamp}.csv`);
}

export function exportScanAsPdf(scan: WebsiteScan) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 44;
  const maxWidth = pageWidth - margin * 2;
  let y = 52;

  const ensureSpace = (needed: number) => {
    if (y + needed > pageHeight - 50) {
      doc.addPage();
      y = 50;
    }
  };

  // Header Branding
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(15, 23, 42);
  doc.text('ORIGINSEC 2.0', margin, y);
  doc.setFontSize(9.5);
  doc.setTextColor(0, 140, 85);
  doc.text('REAL-TIME DIAGNOSTICS, NO FLUFF  |  A DOPTAILS COMPANY', margin + 140, y);

  y += 22;
  doc.setDrawColor(220, 220, 220);
  doc.line(margin, y, pageWidth - margin, y);
  y += 24;

  // Report Metadata & Assessment Scope
  doc.setFontSize(16);
  doc.setTextColor(15, 23, 42);
  doc.text(`Audit Report — ${scan.normalizedDomain}`, margin, y);
  y += 18;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(80, 80, 80);
  doc.text(`Target URL: ${scan.targetUrl}`, margin, y);
  y += 13;
  doc.text(
    `Scan ID: ${scan.scanId}   |   Profile: ${(scan.scanProfile || 'standard').toUpperCase()}   |   Fingerprint: ${scan.postureFingerprint || 'N/A'}`,
    margin,
    y
  );
  y += 13;
  doc.text(
    `Status: ${scan.status.toUpperCase()}   |   Authorization: ${scan.authorizedConfirmed ? 'User Confirmed' : 'Unconfirmed'}   |   Completed: ${scan.completedAt || scan.startedAt}`,
    margin,
    y
  );
  y += 13;
  doc.text(
    `Coverage: ${scan.coverage?.pagesScanned ?? 1} page(s) · HTTPS: ${scan.coverage?.httpsVerified ? 'Yes' : 'No'} · TLS: ${scan.coverage?.tlsVerified ? 'Verified' : 'Unavailable'} · DNS: ${scan.coverage?.dnsVerified ? 'Verified' : 'Unavailable'}`,
    margin,
    y
  );
  y += 22;

  // Executive Summary
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Executive Summary', margin, y);
  y += 14;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(40, 40, 40);
  const summaryLines = doc.splitTextToSize(scan.summary || 'No summary available.', maxWidth);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 13 + 16;

  // Category Scores
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Category Scores (Calculated From Verified Checks)', margin, y);
  y += 16;

  const scoreBoxes = [
    { label: 'Security', val: scan.scores?.security },
    { label: 'Front-End', val: scan.scores?.frontend },
    { label: 'Back-End', val: scan.scores?.backend },
    { label: 'Engagement', val: scan.scores?.engagement },
  ];

  const boxW = (maxWidth - 24) / 4;
  scoreBoxes.forEach((b, i) => {
    const x = margin + i * (boxW + 8);
    doc.setDrawColor(215, 210, 200);
    doc.roundedRect(x, y, boxW, 44, 4, 4);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(15, 23, 42);
    doc.text(b.val !== null && b.val !== undefined ? `${b.val}/100` : 'N/A', x + 10, y + 22);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 100, 100);
    doc.text(b.label.toUpperCase(), x + 10, y + 36);
  });
  y += 58;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(70, 70, 70);
  doc.text(
    `Overall: ${scan.scores?.overall ?? 'N/A'}/100  |  SEO: ${scan.scores?.seo ?? 'N/A'}/100  |  Accessibility: ${scan.scores?.accessibility ?? 'N/A'}/100  |  Performance: ${scan.scores?.performance ?? 'N/A'}/100  |  TTFB: ${scan.metrics?.ttfbMs ?? 'N/A'} ms`,
    margin,
    y
  );
  y += 20;

  // Findings
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text(`Detailed Findings (${(scan.findings || []).length})`, margin, y);
  y += 18;

  for (const f of scan.findings || []) {
    ensureSpace(115);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`[${f.severity.toUpperCase()}] ${f.title} (${f.category.toUpperCase()})`, margin, y);
    y += 13;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(60, 60, 60);
    const descLines = doc.splitTextToSize(`Description: ${f.description}`, maxWidth);
    doc.text(descLines, margin, y);
    y += descLines.length * 11 + 3;

    const evLines = doc.splitTextToSize(`Evidence: ${f.evidence} | Status: ${f.status}`, maxWidth);
    doc.text(evLines, margin, y);
    y += evLines.length * 11 + 3;

    const fixLines = doc.splitTextToSize(`Fix: ${f.recommendation} ${f.remediation ? `(${f.remediation})` : ''}`, maxWidth);
    doc.text(fixLines, margin, y);
    y += fixLines.length * 11 + 3;

    const verLines = doc.splitTextToSize(`Verification: ${f.verification}`, maxWidth);
    doc.text(verLines, margin, y);
    y += verLines.length * 11 + 12;

    doc.setDrawColor(235, 235, 235);
    doc.line(margin, y - 5, pageWidth - margin, y - 5);
  }

  // Methodology & Disclaimer
  ensureSpace(95);
  y += 10;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('Methodology, Limitations & Disclaimer', margin, y);
  y += 14;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(90, 90, 90);
  const disclaimer = doc.splitTextToSize(
    'OriginSec conducts non-destructive external HTTP, TLS, DNS, and static HTML inspections within safe crawl limits. Private databases, hosting dashboards, and backup providers are marked Not assessed unless explicitly authorized via an integration. Founded by Aditya Choudhary | A DopTails Company.',
    maxWidth
  );
  doc.text(disclaimer, margin, y);

  doc.save(`originsec-report-${scan.normalizedDomain}-${scan.scanId}.pdf`);
}
