const API_URL = import.meta.env.VITE_API_URL ?? "/api";

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail ?? `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

export const fetchCoverage = () => request("/coverage");
export const fetchCoverageHistory = (limit = 50) => request(`/coverage/history?limit=${limit}`);
export const fetchAttck = () => request("/coverage/attck");
export const takeSnapshot = () => request("/coverage/snapshot", { method: "POST" });

export const fetchScenarios = () => request("/scenarios");
export const syncScenarios = () => request("/scenarios/sync", { method: "POST" });

export const fetchExecutions = (limit = 100) => request(`/executions?limit=${limit}`);
export const fetchExecution = (id) => request(`/executions/${encodeURIComponent(id)}`);
export const runScenario = (key) =>
  request(`/executions/run/${encodeURIComponent(key)}`, { method: "POST" });
export const runAll = () => request("/executions/run-all", { method: "POST" });

export const fetchRules = () => request("/rules");
export const fetchCollectors = () => request("/collectors");
export const fetchCollectorHealth = () => request("/collectors/health");
export const validateRule = (content) =>
  request("/rules/validate", { method: "POST", body: JSON.stringify({ content }) });

export const api = {
  scenarios: fetchScenarios,
  executions: fetchExecutions,
  coverage: fetchCoverage,
  coverageHistory: fetchCoverageHistory,
  attck: fetchAttck,
  rules: fetchRules,
  collectors: fetchCollectors,
  collectorHealth: fetchCollectorHealth,
  runScenario,
  runAll,
  takeSnapshot,
  syncScenarios,
  execution: fetchExecution,
};

export default api;