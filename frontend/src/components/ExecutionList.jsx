import { Check, CircleX, Clock3, Eye } from "lucide-react";

const passingOutcomes = new Set(["detected", "negative_pass"]);
const outcomeLabel = (outcome) => (outcome ?? "not_tested").replaceAll("_", " ").toUpperCase();

export default function ExecutionList({ executions, limit = 5, onSelect }) {
  if (!executions.length) return <p className="empty-state">No executions yet. Run a scenario to see results.</p>;
  return (
    <div className="execution-list">
      {executions.slice(0, limit).map((run) => (
        <div className="execution-row" key={run.id}>
          <span className={`result-icon ${passingOutcomes.has(run.outcome) ? "success" : run.outcome?.includes("fail") ? "failed" : "pending"}`}>
            {passingOutcomes.has(run.outcome) ? <Check size={14} /> : <CircleX size={14} />}
          </span>
          <div className="execution-copy">
            <strong>{run.scenario_key ?? run.scenario_id}</strong>
            <span>{run.matched_rule_keys?.length ? run.matched_rule_keys.join(", ") : "No rules matched"}</span>
          </div>
          <span className={`result-label ${passingOutcomes.has(run.outcome) ? "success-text" : run.outcome?.includes("fail") ? "failed-text" : "pending-text"}`}>
            {outcomeLabel(run.outcome)}
          </span>
          <span className="run-time"><Clock3 size={13} />{run.detection_latency_ms == null ? "--" : `${run.detection_latency_ms.toFixed(1)} ms`}</span>
          {onSelect && <button className="icon-button" title="View execution details" aria-label="View execution details" onClick={() => onSelect(run.id)}><Eye size={14} /></button>}
        </div>
      ))}
    </div>
  );
}