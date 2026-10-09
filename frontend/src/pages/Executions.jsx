import { useState } from "react";
import { ListChecks } from "lucide-react";
import { fetchExecution } from "../api/client.js";
import ExecutionList from "../components/ExecutionList.jsx";

export default function Executions({ executions }) {
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  async function selectExecution(id) {
    try { setSelected(await fetchExecution(id)); setError(""); }
    catch (loadError) { setError(loadError.message); }
  }
  return <>
    <div className="page-heading"><div><div className="eyebrow">ACTIVITY / RUN HISTORY</div><h1>Executions</h1><p>Review outcomes and matched rules for each scenario run.</p></div><div className="heading-meta"><ListChecks size={15} /> {executions.length} RUNS</div></div>
    {error && <div className="error-banner" role="alert">{error}</div>}
    <section className="panel full-panel"><div className="panel-title"><h2>Execution history</h2><span className="table-note">Newest first</span></div><ExecutionList executions={executions} limit={executions.length || 5} onSelect={selectExecution} /></section>
    {selected && <section className="panel detail-panel"><div className="panel-title"><h2>Execution detail</h2><span className="table-note">{selected.run_id}</span></div><div className="detail-content"><dl className="detail-grid"><dt>Outcome</dt><dd>{selected.outcome}</dd><dt>Status</dt><dd>{selected.status}</dd><dt>Telemetry</dt><dd>{selected.telemetry_available ? "Available" : "Unavailable"}</dd><dt>Matched rules</dt><dd>{selected.matched_rule_keys.join(", ") || "None"}</dd></dl><h3>Alerts ({selected.alerts.length})</h3>{selected.alerts.map((alert, index) => <div className="detail-row" key={`${alert.rule_key}-${index}`}><strong>{alert.title}</strong><span>{alert.rule_key} · {alert.severity}</span></div>)}<details><summary>Evidence ({selected.evidence.length} records)</summary><pre>{JSON.stringify(selected.evidence, null, 2)}</pre></details></div></section>}
  </>;
}