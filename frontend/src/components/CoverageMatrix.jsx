export default function CoverageMatrix({ coverage }) {
  const techniques = Object.entries(coverage?.by_technique ?? {});
  if (!techniques.length) return <p className="empty-state">Coverage appears after a scenario execution.</p>;
  return (
    <div className="coverage-table-wrap">
      <table className="coverage-table">
        <thead><tr><th>Technique</th><th>Total</th><th>Detected</th><th>Failed</th><th>Telemetry missing</th><th>Coverage</th></tr></thead>
        <tbody>{techniques.map(([technique, metric]) => (
          <tr key={technique}><td><code>{technique}</code></td><td>{metric.total}</td><td>{metric.detected}</td><td>{metric.failed}</td><td>{metric.telemetry_unavailable}</td><td><div className="coverage-track"><i style={{ width: `${metric.coverage_percent}%` }} /></div><span className="coverage-percent">{metric.coverage_percent}%</span></td></tr>
        ))}</tbody>
      </table>
    </div>
  );
}