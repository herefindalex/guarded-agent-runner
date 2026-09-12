import { FormEvent, useMemo, useState } from 'react';

type Action = {
  id: string;
  action: string;
  args: Record<string, unknown>;
  purpose?: string;
  status: string;
  result?: unknown;
  failure_reason?: string;
};

type Approval = {
  id: string;
  action: string;
  args: Record<string, unknown>;
  resource: string;
  scope_hash: string;
  status: string;
  expires_at: string;
};

type Run = {
  id: string;
  user_id: string;
  request: string;
  workflow: Workflow;
  target_service: ServiceName;
  status: string;
  scope: {
    allowed_services: string[];
    allowed_actions: string[];
    approval_policy: Array<{ action: string; mode: string }>;
    version: number;
    hash: string;
  };
  plan: Action[];
  current_step: number;
  expires_at: string;
  last_error?: string;
  pending_approval?: Approval;
};

type AuditEvent = {
  id: number;
  actor: string;
  event_type: string;
  action?: string;
  resource?: string;
  metadata: Record<string, unknown>;
  timestamp: string;
};

const terminal = new Set(['COMPLETED', 'FAILED', 'EXPIRED', 'REJECTED', 'CANCELLED']);

type Workflow = 'status_only' | 'logs_only' | 'status_and_logs' | 'diagnose_and_restart';
type ServiceName = 'nginx' | 'postgresql' | 'mysql' | 'redis';
type PlannerStage = 'idle' | 'submitting' | 'compiled';

const services: Array<{ value: ServiceName; label: string }> = [
  { value: 'nginx', label: 'NGINX · restart auto-authorized' },
  { value: 'postgresql', label: 'PostgreSQL · approval if restart needed' },
  { value: 'mysql', label: 'MySQL · approval if restart needed' },
  { value: 'redis', label: 'Redis · approval if restart needed' },
];

const workflows: Array<{ value: Workflow; label: string; description: string }> = [
  {
    value: 'status_only',
    label: 'Check service status',
    description: 'One low-risk service_status action. No approval required.',
  },
  {
    value: 'logs_only',
    label: 'Read service logs',
    description: 'Read the latest 100 log lines. No approval required.',
  },
  {
    value: 'status_and_logs',
    label: 'Check status and logs',
    description: 'Run both low-risk diagnostic actions.',
  },
  {
    value: 'diagnose_and_restart',
    label: 'Diagnose and restart service',
    description: 'Diagnose, remediate only if needed, then verify the outcome.',
  },
];

const serviceNames: Record<ServiceName, string> = {
  nginx: 'NGINX',
  postgresql: 'PostgreSQL',
  mysql: 'MySQL',
  redis: 'Redis',
};

function requestTemplate(workflow: Workflow, service: ServiceName): string {
  const name = serviceNames[service];
  if (workflow === 'status_only') return `Check the current status of ${name}.`;
  if (workflow === 'logs_only') return `Read the latest 100 log lines for ${name}.`;
  if (workflow === 'status_and_logs') return `Check ${name} status and inspect its latest logs.`;
  return `Diagnose ${name} and restart it if necessary.`;
}

async function api<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail ?? `Request failed (${response.status})`);
  return body;
}

function resultObject(action?: Action): Record<string, unknown> | null {
  return action?.result && typeof action.result === 'object'
    ? action.result as Record<string, unknown>
    : null;
}

function actionPurpose(purpose?: string): string {
  return {
    observe_current_state: 'Observe current state',
    diagnose_current_state: 'Diagnose current state',
    inspect_recent_evidence: 'Inspect recent evidence',
    remediate_if_needed: 'Remediate only if needed',
    verify_outcome: 'Verify desired outcome',
  }[purpose ?? ''] ?? 'Execute scoped action';
}

function actionResult(action: Action): string | null {
  const result = resultObject(action);
  if (!result) return null;
  if (action.status === 'SKIPPED') return `Skipped · ${String(result.reason)}`;
  if (action.action === 'service_status' && result.status) {
    const prefix = action.purpose === 'verify_outcome' ? 'Verified' : 'Observed';
    return `${prefix}: ${String(result.status).toUpperCase()}`;
  }
  if (action.action === 'read_log' && Array.isArray(result.lines)) {
    const latest = result.lines.at(-1);
    return latest ? `Evidence: ${String(latest)}` : 'Evidence: no recent log lines';
  }
  if (action.action === 'restart_service' && result.restarted) {
    return `Restarted · resulting state: ${String(result.status).toUpperCase()}`;
  }
  return JSON.stringify(result);
}

function runOutcome(run: Run): { tone: string; title: string; detail: string } | null {
  const remediation = run.plan.find((action) => action.purpose === 'remediate_if_needed');
  const verification = run.plan.find((action) => action.purpose === 'verify_outcome');
  const observed = run.plan.find((action) => action.purpose === 'diagnose_current_state');
  const observedStatus = resultObject(observed)?.status;

  if (run.status === 'WAITING_APPROVAL') {
    return {
      tone: 'approval',
      title: 'Remediation required · human approval',
      detail: `${serviceNames[run.target_service]} was observed ${String(observedStatus ?? 'unhealthy').toLowerCase()}; execution is paused before restart.`,
    };
  }
  if (run.status === 'APPROVED') {
    return {
      tone: 'approval',
      title: 'Approved · not yet executed',
      detail: 'Resume will revalidate the exact action and scope before touching infrastructure.',
    };
  }
  if (run.status === 'COMPLETED' && remediation?.status === 'SKIPPED') {
    return {
      tone: 'healthy',
      title: 'Healthy · no restart was necessary',
      detail: `${serviceNames[run.target_service]} remained running; the state-changing action was explicitly skipped.`,
    };
  }
  if (run.status === 'COMPLETED' && remediation?.status === 'SUCCEEDED' && resultObject(verification)?.status === 'running') {
    return {
      tone: 'recovered',
      title: 'Recovered · service verified running after restart',
      detail: `${serviceNames[run.target_service]} remediation completed and the follow-up observation proved the desired state.`,
    };
  }
  if (run.status === 'COMPLETED') {
    return {
      tone: 'healthy',
      title: 'Observation complete',
      detail: 'All requested read-only infrastructure checks completed within scope.',
    };
  }
  return null;
}

function App() {
  const [userId, setUserId] = useState('alex');
  const [workflow, setWorkflow] = useState<Workflow>('diagnose_and_restart');
  const [targetService, setTargetService] = useState<ServiceName>('nginx');
  const [operatorRequest, setOperatorRequest] = useState(() => requestTemplate('diagnose_and_restart', 'nginx'));
  const [showReadonlyNotice, setShowReadonlyNotice] = useState(false);
  const [plannerStage, setPlannerStage] = useState<PlannerStage>('idle');
  const [run, setRun] = useState<Run | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const approval = run?.pending_approval?.status === 'PENDING' ? run.pending_approval : null;
  const selectedWorkflow = workflows.find((option) => option.value === workflow)!;
  const intentDescription = workflow === 'diagnose_and_restart'
    ? targetService === 'nginx'
      ? 'Diagnose first; auto-authorize an NGINX restart only if recovery is needed.'
      : `Diagnose first; if ${serviceNames[targetService]} needs a restart, pause for human approval.`
    : selectedWorkflow.description;
  const outcome = run ? runOutcome(run) : null;
  const primaryLabel = useMemo(() => {
    if (!run) return 'Create guarded run';
    if (run.status === 'APPROVED') return 'Resume with revalidation';
    return 'Execute next step';
  }, [run]);

  async function refreshAudit(runId: string) {
    setAudit(await api<AuditEvent[]>(`/runs/${runId}/audit`));
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    setPlannerStage('submitting');
    const succeeded = await perform(async () => {
      const created = await api<Run>('/runs', {
        method: 'POST',
        body: JSON.stringify({
          user_id: userId,
          request: operatorRequest.trim(),
          workflow,
          target_service: targetService,
        }),
      });
      setRun(created);
      setPlannerStage('compiled');
      const advanced = await api<Run>(`/runs/${created.id}/run`, { method: 'POST' });
      setRun(advanced);
      await refreshAudit(advanced.id);
    });
    if (!succeeded) setPlannerStage('idle');
  }

  async function step() {
    if (!run) return;
    await perform(async () => {
      const updated = await api<Run>(`/runs/${run.id}/step`, { method: 'POST' });
      setRun(updated);
      await refreshAudit(updated.id);
    });
  }

  async function decide(decision: 'approve' | 'reject') {
    if (!run || !approval) return;
    await perform(async () => {
      const updated = await api<Run>(`/approvals/${approval.id}/${decision}`, {
        method: 'POST',
        body: JSON.stringify({ actor: userId }),
      });
      setRun(updated);
      await refreshAudit(updated.id);
    });
  }

  async function perform(work: () => Promise<void>): Promise<boolean> {
    setBusy(true);
    setError('');
    try {
      await work();
      return true;
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Unknown request error');
      return false;
    } finally {
      setBusy(false);
    }
  }

  function chooseService(service: ServiceName) {
    setTargetService(service);
    setOperatorRequest(requestTemplate(workflow, service));
    setShowReadonlyNotice(false);
  }

  function chooseWorkflow(nextWorkflow: Workflow) {
    setWorkflow(nextWorkflow);
    setOperatorRequest(requestTemplate(nextWorkflow, targetService));
    setShowReadonlyNotice(false);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-mark">GA</div>
        <div>
          <p className="eyebrow">SECURE EXECUTION CONTROL PLANE</p>
          <h1>Guarded Agent Runner</h1>
        </div>
        <span className="trust-chip"><i /> Planner is untrusted</span>
      </header>

      <section className="hero">
        <div>
          <p className="kicker">CAPABILITY-BOUNDED BY DESIGN</p>
          <h2>Proposals ≠ permissions.</h2>
          <p>Every requested action crosses policy, scope and approval boundaries before the guarded executor can touch infrastructure.</p>
          <div className="concept-note"><strong>CONCEPT VALIDATION MVP · NO LLM CONNECTED</strong><span>Uses a deterministic preset planner to validate capability, approval, revalidation and audit controls.</span></div>
        </div>
        <div className="invariant"><span>CORE INVARIANT</span><strong>scope(t+1) ⊆ scope(t)</strong></div>
      </section>

      <div className="workspace">
        <section className="panel request-panel">
          <div className="panel-heading"><span>01</span><h3>Operator request</h3></div>
          <form onSubmit={create}>
            <label>User identity<input value={userId} onChange={(event) => setUserId(event.target.value)} required /></label>
            <label>Target service
              <select value={targetService} onChange={(event) => chooseService(event.target.value as ServiceName)}>
                {services.map((service) => <option value={service.value} key={service.value}>{service.label}</option>)}
              </select>
            </label>
            <label>Infrastructure intent
              <select value={workflow} onChange={(event) => chooseWorkflow(event.target.value as Workflow)}>
                {workflows.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
              </select>
            </label>
            <p className="intent-help">{intentDescription}</p>
            <label>Operator request
              <textarea
                className="readonly-request"
                value={operatorRequest}
                readOnly
                onClick={() => setShowReadonlyNotice(true)}
                onFocus={() => setShowReadonlyNotice(true)}
                onKeyDown={() => setShowReadonlyNotice(true)}
                aria-describedby="readonly-request-note"
              />
            </label>
            <p id="readonly-request-note" className={`request-hint ${showReadonlyNotice ? 'notice' : ''}`} aria-live="polite">
              {showReadonlyNotice
                ? 'NO LLM CONNECTED — Operator request is read-only because this is a concept-validation prototype MVP.'
                : 'Generated from the controlled selections above. This prototype does not interpret free-form text.'}
            </p>
            <p className="request-boundary"><strong>PROPOSAL ONLY</strong> Request text never grants capability or approval.</p>
            <button className="primary" disabled={busy}>{busy ? plannerStage === 'submitting' ? 'Generating typed proposal…' : 'Running guarded workflow…' : 'Run guarded demo'}</button>
          </form>
          {error && <p className="error">{error}</p>}
        </section>

        <section className="panel scope-panel">
          <div className="panel-heading"><span>02</span><h3>Agent-style processing &amp; scope</h3></div>
          <div className={`planner-state ${plannerStage}`} aria-live="polite">
            <div className="planner-state-heading"><i /><strong>{plannerStage === 'idle' ? 'AWAITING GENERATED REQUEST' : plannerStage === 'submitting' ? 'GENERATING PRESET PLAN' : 'POLICY EVALUATION COMPLETE'}</strong></div>
            <div className="planner-pipeline" aria-label="Deterministic planner processing stages">
              <span className={plannerStage !== 'idle' ? 'done' : ''}>Request generated</span>
              <span className={plannerStage === 'submitting' ? 'active' : plannerStage === 'compiled' ? 'done' : ''}>Preset plan generated</span>
              <span className={plannerStage === 'compiled' ? 'done' : ''}>Scope compiled</span>
              <span className={plannerStage === 'compiled' ? 'done' : ''}>Policy evaluated</span>
            </div>
            {plannerStage === 'idle' && <p>Submit the generated operator request to start the agent-style simulation.</p>}
            {plannerStage === 'submitting' && <p>Mapping the controlled selections into typed, capability-bounded tool calls…</p>}
            {plannerStage === 'compiled' && run && <>
              <small>GENERATED REQUEST RECEIVED</small>
              <p className="planner-request">“{run.request}”</p>
              <div className="interpretation-result"><span><small>TARGET</small><code>{run.target_service}</code></span><span><small>WORKFLOW</small><code>{workflows.find((option) => option.value === run.workflow)?.label}</code></span></div>
            </>}
            <small className="simulation-label">AGENT-STYLE SIMULATION · DETERMINISTIC PRESET PLANNER · NO LLM CONNECTED</small>
          </div>
          {run ? <>
            <div className="scope-group"><small>ALLOWED RESOURCE</small><code>service:{run.target_service}</code></div>
            <div className="scope-group"><small>ALLOWED ACTIONS</small>{run.scope.approval_policy.map((rule) => <div className="rule" key={rule.action}><code>{rule.action}</code><b className={rule.mode}>{rule.mode}</b></div>)}</div>
            <div className="hash"><small>SCOPE HASH · V{run.scope.version}</small><code>{run.scope.hash}</code></div>
          </> : <p className="empty">Create a run to compile an immutable scope.</p>}
        </section>

        <section className="panel plan-panel">
          <div className="panel-heading"><span>03</span><h3>Action plan</h3>{run && <b className={`status ${run.status.toLowerCase()}`}>{run.status}</b>}</div>
          {run ? <>
            {outcome && <div className={`outcome ${outcome.tone}`} role="status">
              <strong>{outcome.title}</strong>
              <p>{outcome.detail}</p>
            </div>}
            <div className="actions">{run.plan.map((action, index) => <article className={`action ${action.status.toLowerCase()}`} key={action.id}>
              <div className="action-index">{String(index + 1).padStart(2, '0')}</div>
              <div>
                <small className="action-purpose">{actionPurpose(action.purpose)}</small>
                <code>{action.action}</code>
                <p>{JSON.stringify(action.args)}</p>
                {actionResult(action) && <p className="action-result">{actionResult(action)}</p>}
                {action.failure_reason && <em>{action.failure_reason}</em>}
              </div>
              <span>{action.status.replaceAll('_', ' ')}</span>
            </article>)}</div>
            <button className="primary" onClick={step} disabled={busy || terminal.has(run.status) || run.status === 'WAITING_APPROVAL'}>{primaryLabel}</button>
            {run.last_error && <p className="error">{run.last_error}</p>}
          </> : <p className="empty">The deterministic planner will produce the selected typed action plan.</p>}
        </section>

        <section className={`panel approval-panel ${approval ? 'active' : ''}`}>
          <div className="panel-heading"><span>04</span><h3>Human approval</h3></div>
          {approval ? <>
            <div className="risk">HIGH RISK ACTION</div>
            <h4>{approval.action}</h4>
            <div className="approval-context">
              <strong>Why approval is needed</strong>
              <p>Diagnostics found {serviceNames[run!.target_service]} unhealthy. This state-changing restart exceeds automatic privilege for the selected service.</p>
              <strong>Expected impact</strong>
              <p>Restart only <code>service:{approval.resource}</code>, then perform a read-only status check to verify recovery.</p>
            </div>
            <dl><div><dt>Resource</dt><dd>{approval.resource}</dd></div><div><dt>Arguments</dt><dd>{JSON.stringify(approval.args)}</dd></div><div><dt>Expires</dt><dd>{new Date(approval.expires_at).toLocaleTimeString()}</dd></div></dl>
            <p className="binding">Bound to scope <code>{approval.scope_hash.slice(0, 16)}…</code></p>
            <div className="decision"><button className="reject" onClick={() => decide('reject')} disabled={busy}>Reject</button><button className="approve" onClick={() => decide('approve')} disabled={busy}>Approve exact action</button></div>
          </> : <p className="empty">Privileged actions pause here. Approval never triggers execution directly.</p>}
        </section>

        <section className="panel audit-panel">
          <div className="panel-heading"><span>05</span><h3>Append-only audit trail</h3><small>{audit.length} EVENTS</small></div>
          {audit.length ? <ol>{audit.map((event) => <li key={event.id}>
            <time>{new Date(event.timestamp).toLocaleTimeString()}</time><i className={event.event_type.includes('FAILED') || event.event_type.includes('DENIED') ? 'bad' : ''} />
            <div><strong>{event.event_type}</strong><p>{event.actor}{event.action ? ` · ${event.action}` : ''}{event.resource ? ` · ${event.resource}` : ''}</p></div>
          </li>)}</ol> : <p className="empty">Externally visible decisions and actions appear here in order.</p>}
        </section>
      </div>
    </main>
  );
}

export default App;
