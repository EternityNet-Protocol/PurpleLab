import { useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import { syncScenarios } from "../api/client.js";
import ScenarioList from "../components/ScenarioList.jsx";

export default function Scenarios({ scenarios, onRun, onRefresh }) {
  const [runningId, setRunningId] = useState("");
  const [syncing, setSyncing] = useState(false);
  async function run(id) {
    setRunningId(id);
    try { await onRun(id); } finally { setRunningId(""); }
  }
  async function sync() {
    setSyncing(true);
    try { await syncScenarios(); await onRefresh(); } finally { setSyncing(false); }
  }
  return <>
    <div className="page-heading"><div><div className="eyebrow">LIBRARY / FIXTURE SCENARIOS</div><h1>Scenarios</h1><p>Run controlled event fixtures against the local detection rules.</p></div><div className="heading-actions"><span className="heading-meta"><FlaskConical size={15} /> {scenarios.length} AVAILABLE</span><button className="secondary-button" disabled={syncing} onClick={sync}><RefreshCw size={14} /> Sync from disk</button></div></div>
    <section className="panel full-panel"><div className="panel-title"><h2>Scenario library</h2><span className="fixture-tag">FIXTURE MODE</span></div><ScenarioList scenarios={scenarios} onRun={run} runningId={runningId} /></section>
  </>;
}