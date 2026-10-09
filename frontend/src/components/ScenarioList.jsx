import { Activity, ArrowUpRight, Play } from "lucide-react";

export default function ScenarioList({ scenarios, onRun, compact = false, runningId = "" }) {
  if (!scenarios.length) return <p className="empty-state">No scenarios are configured.</p>;
  const visibleScenarios = compact ? scenarios.slice(0, 4) : scenarios;
  return (
    <div className="scenario-list">
      {visibleScenarios.map((scenario) => (
        <article className="scenario-row" key={scenario.id}>
          <div className="scenario-icon"><Activity size={17} /></div>
          <div className="scenario-copy">
            <strong>{scenario.name}</strong>
            <span>{scenario.attck_technique ?? "Unmapped"} · {scenario.severity}{scenario.is_negative_control ? " · negative control" : ""}</span>
          </div>
          <span className="fixture-tag">FIXTURE</span>
          {onRun && <button className="icon-button run-button" title={`Run ${scenario.name}`} aria-label={`Run ${scenario.name}`} disabled={runningId === scenario.key} onClick={() => onRun(scenario.key)}><Play size={15} fill="currentColor" /></button>}
          {!onRun && <ArrowUpRight className="row-arrow" size={16} />}
        </article>
      ))}
    </div>
  );
}