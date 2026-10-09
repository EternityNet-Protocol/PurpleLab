import { useEffect, useState } from "react";
import { Activity, Boxes, CircleHelp, FlaskConical, LayoutDashboard, ListChecks } from "lucide-react";
import { api } from "./api/client.js";
import Dashboard from "./pages/Dashboard.jsx";
import Scenarios from "./pages/Scenarios.jsx";
import Executions from "./pages/Executions.jsx";

const navigation = [
  { id: "dashboard", label: "Overview", icon: LayoutDashboard },
  { id: "scenarios", label: "Scenarios", icon: FlaskConical },
  { id: "executions", label: "Executions", icon: ListChecks },
];

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [data, setData] = useState({ scenarios: [], executions: [], coverage: null, history: [], attck: [], rules: [], collectors: null, collectorHealth: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const [scenarios, executions, coverage, history, attckResponse, rules, collectors, collectorHealth] = await Promise.all([
        api.scenarios(), api.executions(), api.coverage(), api.coverageHistory(), api.attck(), api.rules(), api.collectors(), api.collectorHealth(),
      ]);
      setData({ scenarios, executions, coverage, history, attck: attckResponse.techniques, rules, collectors, collectorHealth });
      setError("");
    } catch (loadError) {
      setError(loadError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  async function runScenario(scenarioId) {
    try {
      await api.runScenario(scenarioId);
      await refresh();
    } catch (runError) {
      setError(runError.message);
    }
  }

  async function runAll() {
    try {
      await api.runAll();
      setError("Eligible scenarios scheduled. Refresh execution history shortly.");
      window.setTimeout(refresh, 1200);
    } catch (runError) {
      setError(runError.message);
    }
  }

  async function takeSnapshot() {
    try {
      await api.takeSnapshot();
      await refresh();
    } catch (snapshotError) {
      setError(snapshotError.message);
    }
  }

  const content = page === "scenarios"
    ? <Scenarios scenarios={data.scenarios} onRun={runScenario} onRefresh={refresh} />
    : page === "executions"
      ? <Executions executions={data.executions} />
      : <Dashboard data={data} onRun={runScenario} onRunAll={runAll} onSnapshot={takeSnapshot} onNavigate={setPage} />;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" onClick={() => setPage("dashboard")}>
          <span className="brand-mark"><Activity size={18} /></span>
          <span><strong>PurpleLab</strong><small>DETECTION VALIDATION</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => setPage(id)}>
              <Icon size={17} strokeWidth={1.8} />{label}
              {id === "scenarios" && <span className="nav-count">{data.scenarios.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="collector-status"><span className={`status-dot ${data.collectorHealth?.healthy ? "" : "offline"}`} /> {data.collectors?.configured ?? "fixture"} collector <span>{data.collectorHealth?.healthy ? "READY" : "OFFLINE"}</span></div>
          <div className="sidebar-foot"><Boxes size={15} /> Local workspace <CircleHelp size={15} /></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div><span className="crumb">PurpleLab</span><span className="crumb-divider">/</span><span>{navigation.find((item) => item.id === page)?.label}</span></div>
          <div className="topbar-right"><span className="environment"><i /> {data.collectors?.configured ?? "FIXTURE"} COLLECTOR</span><span className="avatar">PL</span></div>
        </header>
        <section className="page-content">
          {error && <div className="error-banner" role="alert">API unavailable: {error}. Start the backend to load live results.</div>}
          {loading ? <div className="loading-state">Connecting to PurpleLab API...</div> : content}
        </section>
      </main>
    </div>
  );
}