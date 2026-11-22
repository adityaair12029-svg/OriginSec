import React, { useMemo, useState } from 'react';
import { CheckCircle2, RefreshCw, ShieldAlert, Trash2, Wrench } from 'lucide-react';
import type { RemediationTask } from '../types/audit';
import { EmptyWorkspaceState } from './DashboardShell';

interface RemediationWorkspaceViewProps {
  isAuthenticated: boolean;
  onSignIn: () => void;
  tasks: RemediationTask[];
  getAuthToken: () => Promise<string | null>;
  onUpdateTask: (
    taskId: string,
    updates: Partial<Pick<RemediationTask, 'status' | 'priority' | 'notes' | 'dueDate' | 'lastVerifiedAt' | 'verificationResult'>>
  ) => Promise<void>;
  onUpdateFindingStatus: (
    findingId: string,
    updates: { status?: any; remediationNote?: string; dueDate?: string | null; resolvedAt?: string | null }
  ) => Promise<void>;
  onDeleteTask: (taskId: string) => Promise<void>;
  onNotificationTrigger?: (msg: string, domain: string, taskId: string) => Promise<void>;
}

const STATUS_OPTIONS: Array<{ value: RemediationTask['status']; label: string }> = [
  { value: 'open', label: 'Open' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'ready_for_verification', label: 'Ready for Verification' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'accepted_risk', label: 'Accepted Risk' },
];

export const RemediationWorkspaceView: React.FC<RemediationWorkspaceViewProps> = ({
  isAuthenticated,
  onSignIn,
  tasks,
  getAuthToken,
  onUpdateTask,
  onUpdateFindingStatus,
  onDeleteTask,
  onNotificationTrigger,
}) => {
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [domainFilter, setDomainFilter] = useState<string>('all');
  const [editingNotes, setEditingNotes] = useState<Record<string, string>>({});
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verifyFeedback, setVerifyFeedback] = useState<Record<string, string>>({});

  const domains = useMemo(() => Array.from(new Set(tasks.map((t) => t.domain))).sort(), [tasks]);

  const filtered = useMemo(() => {
    return tasks.filter((t) => {
      if (domainFilter !== 'all' && t.domain !== domainFilter) return false;
      if (statusFilter === 'active') return t.status !== 'resolved' && t.status !== 'accepted_risk';
      if (statusFilter !== 'all' && t.status !== statusFilter) return false;
      return true;
    });
  }, [tasks, statusFilter, domainFilter]);

  const handleVerifyLive = async (task: RemediationTask) => {
    setVerifyingId(task.taskId);
    try {
      const token = await getAuthToken();
      const res = await fetch('/api/remediation/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          targetUrl: task.targetUrl,
          ruleId: task.ruleId,
          title: task.title,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setVerifyFeedback((prev) => ({ ...prev, [task.taskId]: data.error || 'Verification check failed.' }));
        return;
      }

      const nextStatus: RemediationTask['status'] = data.resolved ? 'resolved' : 'open';
      await onUpdateTask(task.taskId, {
        status: nextStatus,
        lastVerifiedAt: data.checkedAt,
        verificationResult: data.evidence,
      });
      await onUpdateFindingStatus(task.findingId, {
        status: nextStatus,
        resolvedAt: data.resolved ? data.checkedAt : null,
      }).catch(() => {});

      setVerifyFeedback((prev) => ({
        ...prev,
        [task.taskId]: data.resolved ? `Verified fixed: ${data.evidence}` : `Still open on live target: ${data.evidence}`,
      }));

      if (data.resolved && onNotificationTrigger) {
        await onNotificationTrigger(`Remediation verified for ${task.domain}: ${task.title}`, task.domain, task.taskId);
      }
    } catch (err) {
      setVerifyFeedback((prev) => ({
        ...prev,
        [task.taskId]: err instanceof Error ? err.message : 'Network error verifying fix.',
      }));
    } finally {
      setVerifyingId(null);
    }
  };

  if (!isAuthenticated) {
    return (
      <EmptyWorkspaceState
        title="Sign in to track & verify fixes"
        description="Track security, SEO, and performance findings from open to resolved, add engineering notes, and re-verify fixes directly against live production."
        actionLabel="Sign in with Google"
        onAction={onSignIn}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#0A0A0C] dark:text-white">Remediation Workspace</h1>
          <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] mt-1">
            Assign workflows, document fixes, and run live one-click verification checks against production targets.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter remediation status"
            className="px-3.5 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white cursor-pointer"
          >
            <option value="active">Active Queue</option>
            <option value="all">All Tasks ({tasks.length})</option>
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          {domains.length > 1 && (
            <select
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              aria-label="Filter by domain"
              className="px-3.5 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white cursor-pointer"
            >
              <option value="all">All Domains</option>
              {domains.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyWorkspaceState
          title="No remediation tasks in this view"
          description="Open any Audit Report and click 'Track in Remediation' on a finding to manage its fix workflow and verify resolution live."
        />
      ) : (
        <div className="space-y-4">
          {filtered.map((task) => {
            const noteValue = editingNotes[task.taskId] ?? task.notes;
            return (
              <article
                key={task.taskId}
                className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4"
              >
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Wrench className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3] shrink-0" />
                      <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white">{task.title}</h2>
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase border border-[#E5E7EB] dark:border-white/[0.1]">
                        {task.severity}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6] break-all">
                      {task.domain} · {task.category.toUpperCase()}
                      {task.ruleId ? ` · Rule: ${task.ruleId}` : ''}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <select
                      value={task.status}
                      onChange={(e) => {
                        const s = e.target.value as RemediationTask['status'];
                        void onUpdateTask(task.taskId, { status: s });
                        void onUpdateFindingStatus(task.findingId, { status: s }).catch(() => {});
                      }}
                      aria-label={`Workflow status for ${task.title}`}
                      className="px-3 py-2 rounded-xl text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white cursor-pointer"
                    >
                      {STATUS_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>

                    <button
                      type="button"
                      onClick={() => void handleVerifyLive(task)}
                      disabled={verifyingId === task.taskId}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#0A0A0C] text-white dark:bg-white dark:text-[#070708] hover:opacity-90 disabled:opacity-50 cursor-pointer"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${verifyingId === task.taskId ? 'animate-spin' : ''}`} />
                      {verifyingId === task.taskId ? 'Verifying...' : 'Verify Fix Now'}
                    </button>

                    <button
                      type="button"
                      onClick={() => void onDeleteTask(task.taskId)}
                      aria-label={`Delete task ${task.title}`}
                      className="p-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] text-[#5A606E] dark:text-[#9499A6] hover:text-red-500 cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="md:col-span-2 flex gap-2">
                    <input
                      type="text"
                      value={noteValue}
                      onChange={(e) => setEditingNotes((prev) => ({ ...prev, [task.taskId]: e.target.value }))}
                      placeholder="Add engineering remediation note..."
                      aria-label="Remediation notes"
                      className="flex-1 px-3 py-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        void onUpdateTask(task.taskId, { notes: noteValue });
                        void onUpdateFindingStatus(task.findingId, { remediationNote: noteValue }).catch(() => {});
                      }}
                      className="px-3.5 py-2 rounded-xl font-medium border border-[#E5E7EB] dark:border-white/[0.08] hover:border-[#2F75C3] dark:hover:border-[#2F71E3] cursor-pointer"
                    >
                      Save Note
                    </button>
                  </div>

                  <input
                    type="date"
                    value={task.dueDate || ''}
                    onChange={(e) => {
                      const d = e.target.value || null;
                      void onUpdateTask(task.taskId, { dueDate: d });
                      void onUpdateFindingStatus(task.findingId, { dueDate: d }).catch(() => {});
                    }}
                    aria-label="Target due date"
                    className="px-3 py-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
                  />
                </div>

                {(verifyFeedback[task.taskId] || task.verificationResult) && (
                  <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] px-4 py-2.5 text-xs flex items-start gap-2">
                    {task.status === 'resolved' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                    )}
                    <span className="font-mono text-[#5A606E] dark:text-[#9499A6]">
                      {verifyFeedback[task.taskId] || task.verificationResult}
                    </span>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
};
