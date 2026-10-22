/**
 * CRYPTIQ API Client for FastAPI backend.
 */

const API_BASE = '/api/v1';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchEntities() {
  const res = await fetch(`${API_BASE}/entities`);
  if (!res.ok) {
    throw new Error(`Failed to load entity statistics: HTTP ${res.status}`);
  }
  return res.json();
}

export async function investigateAddress({
  address,
  case_id,
  max_hops = 4,
  taint_model = 'haircut',
  enable_network_fetching = false,
  currency_hint,
  max_fetch_txs = 25,
}) {
  const payload = {
    address,
    case_id: case_id || undefined,
    max_hops: Number(max_hops),
    taint_model,
    enable_network_fetching: Boolean(enable_network_fetching),
    currency_hint: currency_hint || undefined,
    max_fetch_txs: Number(max_fetch_txs),
  };

  const res = await fetch(`${API_BASE}/investigate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Investigation failed: HTTP ${res.status}`);
  }
  return data;
}

export async function fetchCaseReport(caseId) {
  const cleanId = encodeURIComponent(caseId.trim());
  const res = await fetch(`${API_BASE}/cases/${cleanId}`);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Case not found: HTTP ${res.status}`);
  }
  return data;
}
