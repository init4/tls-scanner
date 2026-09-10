const BASE = import.meta.env.VITE_API_BASE || "/api";

export async function runScan({ host, port, sni, timeout }) {
  const res = await fetch(`${BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host, port: Number(port) || 443, sni: sni || null, timeout: timeout || 4 }),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore parse failure */
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function checkHealth() {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw new Error("backend unreachable");
  return res.json();
}
