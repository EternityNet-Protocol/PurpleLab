import { Activity, ArrowRight, Clock3, Radio, ShieldAlert, Target, Zap } from "lucide-react";
import AttckHeatmap from "../components/AttckHeatmap.jsx";
import CoverageMatrix from "../components/CoverageMatrix.jsx";
import ExecutionList from "../components/ExecutionList.jsx";
import ScenarioList from "../components/ScenarioList.jsx";

export default function Dashboard({ data, onRun, onRunAll, onSnapshot, onNavigate }) {
  const coverage = data.coverage ?? {};
  const metrics = [
    { icon: Target, label: "Detection rate", value: `${coverage.detection_rate ?? 0}%`, detail: `${coverage.detected_scenarios ?? 0} detected of ${coverage.eligible_scenarios ?? 0} eligible`, tone: "green" },
    { icon: Radio, label: "Telemetry availability", value: `${coverage.telemetry_availability ?? 0}%`, detail: "runs with collected events", tone: "blue" },
    { icon: Activity, label: "Rule match rate", value: `${coverage.rule_match_rate ?? 0}%`, detail: "runs matching at least one rule", tone: "violet" },
    { icon: ShieldAlert, label: "False-positive rate", value: `${coverage.false_positive_rate ?? 0}%`, detail: `${coverage.negative_failures ?? 0} negative controls alerted`, tone: "amber" },
    { icon: Clock3, label: "Average latency", value: `${coverage.avg_latency_ms ?? 0} ms`, detail: "detection event to alert", tone: "blue" },
    { icon: Zap, label: "Not tested", value: coverage.not_tested ?? 0, detail: "scenarios without a run", tone: "violet" },
  ];
  return (
    <>
      <div className="page-heading">
        <div><div className="eyebrow">DETECTION ENGINEERING / OVERVIEW</div><h1>Validation overview</h1><p>Measure detections against safe, repeatable telemetry fixtures.</p></div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={onSnapshot}>Take snapshot</button>
          <button className="primary-button" onClick={onRunAll}>Run eligible</button>
        </div>
      </div>
      <div className="metric-grid">
        {metrics.map(({ icon: Icon, label, value, detail, tone }) => <Metric key={label} icon={Icon} label={label} value={value} detail={detail} tone={tone} />)}
      </div>
      <div className="dashboard-grid">
        <section className="panel scenario-panel"><PanelTitle title="Scenario library" action="All scenarios" onAction={() => onNavigate("scenarios")} /><ScenarioList scenarios={data.scenarios} onRun={onRun} compact /></section>
        <section className="panel recent-panel"><PanelTitle title="Recent executions" action="History" onAction={() => onNavigate("executions")} /><ExecutionList executions={data.executions} limit={4} /></section>
        <section className="panel coverage-panel"><PanelTitle title="ATT&CK coverage" /><AttckHeatmap coverage={coverage} reference={data.attck} /></section>
        <section className="panel coverage-detail"><PanelTitle title="Coverage by technique" /><CoverageMatrix coverage={coverage} /></section>
        <section className="panel trend-panel"><PanelTitle title="Detection trend" /><CoverageTrend history={data.history} /></section>
      </div>
    </>
  );
}

function Metric({ icon: Icon, label, value, detail, tone }) {
  return <article className="metric-card"><span className={`metric-icon ${tone}`}><Icon size={17} /></span><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong><span className="metric-detail">{detail}</span></article>;
}

function PanelTitle({ title, action, onAction }) {
  return <div className="panel-title"><h2>{title}</h2>{action && <button className="text-action" onClick={onAction}>{action}<ArrowRight size={14} /></button>}</div>;
}

function CoverageTrend({ history }) {
  if (!history.length) return <p className="empty-state">Save a coverage snapshot to start a trend.</p>;
  const recent = [...history].reverse().slice(-12);
  return <div className="trend-chart" role="img" aria-label="Detection rate across recent coverage snapshots">
    {recent.map((snapshot) => <div className="trend-column" key={snapshot.taken_at} title={`${snapshot.detection_rate}% · ${new Date(snapshot.taken_at).toLocaleDateString()}`}>
      <span>{snapshot.detection_rate}%</span><i style={{ height: `${Math.max(snapshot.detection_rate, 3)}%` }} />
    </div>)}
  </div>;
}