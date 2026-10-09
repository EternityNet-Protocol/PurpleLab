const groups = ["Execution", "Persistence", "Defense Evasion", "Command and Control"];

export default function AttckHeatmap({ coverage, reference = [] }) {
  const coverageByTechnique = coverage?.by_technique ?? {};
  const techniques = reference.length
    ? reference
    : Object.keys(coverageByTechnique).map((id) => ({ id, name: id, tactic: "Unmapped" }));
  return (
    <div className="heatmap" aria-label="ATT&CK technique coverage">
      <div className="heatmap-head"><span>TACTIC</span><span>TECHNIQUE COVERAGE</span></div>
      {groups.map((group) => {
        const groupEntries = techniques.filter((technique) => technique.tactic.toLowerCase() === group.toLowerCase());
        return <div className="heatmap-row" key={group}><span className="tactic-label">{group}</span><div className="heatmap-cells">{groupEntries.length ? groupEntries.map((technique) => {
          const metric = coverageByTechnique[technique.id] ?? { coverage_percent: 0 };
          return <span className={`heat-cell ${metric.coverage_percent ? "tested" : "untested"}`} title={`${technique.id} ${technique.name}: ${metric.coverage_percent}% tested`} key={technique.id}>{technique.id}</span>;
        }) : <span className="heat-empty">No mapped scenarios</span>}</div></div>;
      })}
    </div>
  );
}