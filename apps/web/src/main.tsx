import { useCallback, useEffect, useState, type FormEvent } from "react";
import ReactDOM from "react-dom/client";

import "./styles.css";

const API_BASE = (import.meta as ImportMeta & { env: { VITE_API_URL?: string } }).env.VITE_API_URL ?? "http://localhost:4000/api/v1";

type User = { id: string; email: string; displayName: string };
type Organization = { id: string; name: string; slug: string };
type EventRow = { id: string; occurredAt: string; source: string; eventType: string; severity: string; outcome: string | null; hostname: string | null; username: string | null };
type Overview = {
  metrics: { eventsLast24Hours: number; eventsPrevious24Hours: number; eventVolumeChange: number | null; highSeverityLast24Hours: number };
  bySeverity: Record<string, number>;
  recentEvents: EventRow[];
};

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantSlug, setTenantSlug] = useState("enterprise-soc");
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const loadOverview = useCallback(async (token: string) => {
    const response = await fetch(`${API_BASE}/dashboard/overview`, {
      headers: { authorization: `Bearer ${token}` },
      credentials: "include",
    });
    if (response.status === 401) {
      const refreshed = await fetch(`${API_BASE}/auth/refresh`, { method: "POST", credentials: "include" });
      if (!refreshed.ok) throw new Error("Your session expired. Please sign in again.");
      const refreshBody = await refreshed.json() as { data: { accessToken: string } };
      setAccessToken(refreshBody.data.accessToken);
      return loadOverview(refreshBody.data.accessToken);
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(body?.error?.message ?? "Unable to load SOC dashboard.");
    }
    const body = await response.json() as { data: Overview };
    setOverview(body.data);
    setLastUpdated(new Date().toISOString());
  }, []);

  useEffect(() => {
    if (!accessToken) return;
    let active = true;
    const refresh = async () => {
      try { await loadOverview(accessToken); }
      catch (cause) {
        if (active) {
          setError(cause instanceof Error ? cause.message : "Dashboard request failed.");
          if (cause instanceof Error && cause.message.includes("session expired")) {
            setAccessToken(null); setUser(null); setOrganization(null); setOverview(null);
          }
        }
      }
    };
    void refresh();
    const interval = window.setInterval(() => { if (active) void refresh(); }, 30_000);
    return () => { active = false; window.clearInterval(interval); };
  }, [accessToken, loadOverview]);

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password, tenantSlug }),
      });
      const body = await response.json() as { data?: { accessToken: string; user: User; organization: Organization }; error?: { message?: string } };
      if (!response.ok || !body.data) throw new Error(body.error?.message ?? "Sign-in failed.");
      setAccessToken(body.data.accessToken); setUser(body.data.user); setOrganization(body.data.organization);
      setPassword(""); setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed.");
    } finally { setBusy(false); }
  }

  async function signOut() {
    if (accessToken) {
      await fetch(`${API_BASE}/auth/logout`, { method: "POST", credentials: "include", headers: { authorization: `Bearer ${accessToken}` } }).catch(() => undefined);
    }
    setAccessToken(null); setUser(null); setOrganization(null); setOverview(null);
  }

  if (!accessToken) {
    return <main className="auth-shell">
      <section className="auth-card">
        <div className="brand-mark">S</div>
        <p className="eyebrow">SECURITY OPERATIONS PLATFORM</p>
        <h1>Sentinel Command</h1>
        <p className="muted">Sign in to your organization's security operations workspace.</p>
        <form onSubmit={signIn}>
          <label>Organization slug<input value={tenantSlug} onChange={(e) => setTenantSlug(e.target.value)} required autoComplete="organization" /></label>
          <label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username" /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" /></label>
          {error && <p className="error" role="alert">{error}</p>}
          <button disabled={busy}>{busy ? "Signing in…" : "Sign in securely"}</button>
        </form>
        <p className="fineprint">Access tokens remain in memory. Refresh sessions use an HttpOnly cookie.</p>
      </section>
    </main>;
  }

  const metrics = overview?.metrics;
  const severities = ["critical", "high", "medium", "low", "info"];
  return <main className="shell">
    <header className="topbar">
      <div className="brand-mark">S</div>
      <div><p className="eyebrow">SECURITY OPERATIONS PLATFORM</p><h1>Sentinel Command</h1></div>
      <div className="account"><span>{organization?.name} · {user?.displayName}</span><button className="secondary" onClick={signOut}>Sign out</button></div>
    </header>
    <section className="page-heading">
      <div><p className="eyebrow">DETECT · ANALYSE · RESPOND · COMPLY</p><h2>Security overview</h2><p className="muted">Live operational telemetry for {organization?.name ?? "your organization"}.</p></div>
      <div className="live-pill"><span className="status-dot" /> Refreshes every 30 seconds</div>
    </section>
    {error && <p className="error banner" role="alert">{error}</p>}
    <section className="metrics-grid">
      <article className="metric-card"><span>Events · last 24h</span><strong>{metrics?.eventsLast24Hours ?? "—"}</strong><small>Previous 24h: {metrics?.eventsPrevious24Hours ?? "—"}</small></article>
      <article className="metric-card"><span>Volume change</span><strong>{metrics?.eventVolumeChange === null ? "—" : metrics?.eventVolumeChange !== undefined ? `${metrics.eventVolumeChange > 0 ? "+" : ""}${metrics.eventVolumeChange}%` : "—"}</strong><small>Compared with prior period</small></article>
      <article className="metric-card"><span>High / critical events</span><strong>{metrics?.highSeverityLast24Hours ?? "—"}</strong><small>Last 24 hours</small></article>
      <article className="metric-card"><span>Telemetry status</span><strong className="healthy">Connected</strong><small>{lastUpdated ? `Updated ${new Date(lastUpdated).toLocaleTimeString()}` : "Loading overview…"}</small></article>
    </section>
    <section className="content-grid">
      <article className="panel"><div className="panel-heading"><h3>Severity distribution</h3><span>Last 24 hours</span></div>
        {severities.map((severity) => {
          const count = overview?.bySeverity[severity] ?? 0;
          const total = Object.values(overview?.bySeverity ?? {}).reduce((sum, value) => sum + value, 0);
          return <div className="severity-row" key={severity}><span className={`severity-dot ${severity}`} /><span className="severity-name">{severity}</span><div className="bar-track"><div className={`bar-fill ${severity}`} style={{ width: `${total ? count / total * 100 : 0}%` }} /></div><strong>{count}</strong></div>;
        })}
      </article>
      <article className="panel"><div className="panel-heading"><h3>Recent security events</h3><span>{overview?.recentEvents.length ?? 0} records</span></div>
        <div className="event-list">
          {!overview?.recentEvents.length && <p className="empty">No security events in the feed yet.</p>}
          {overview?.recentEvents.map((event) => <div className="event-row" key={event.id}><div className={`severity-dot ${event.severity}`} /><div className="event-main"><strong>{event.eventType}</strong><span>{event.hostname ?? event.source}{event.username ? ` · ${event.username}` : ""}</span></div><time>{new Date(event.occurredAt).toLocaleTimeString()}</time><em className={`tag ${event.severity}`}>{event.severity}</em></div>)}
        </div>
      </article>
    </section>
    <footer>Enterprise AI-Powered Cyber Security Operations Command Center · Data is tenant-scoped and API-authorized.</footer>
  </main>;
}

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
