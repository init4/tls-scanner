import React, { useState } from "react";
import ScanForm from "./components/ScanForm.jsx";
import GradeBadge from "./components/GradeBadge.jsx";
import PqcGauge from "./components/PqcGauge.jsx";
import ProtocolTable from "./components/ProtocolTable.jsx";
import CipherList from "./components/CipherList.jsx";
import CertificatePanel from "./components/CertificatePanel.jsx";
import PqcGroupsPanel from "./components/PqcGroupsPanel.jsx";
import LegacyChecksPanel from "./components/LegacyChecksPanel.jsx";
import HttpHeadersPanel from "./components/HttpHeadersPanel.jsx";
import FindingsList from "./components/FindingsList.jsx";
import RawJsonPanel from "./components/RawJsonPanel.jsx";
import { runScan } from "./api.js";

export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(params) {
    setLoading(true);
    setError(null);
    try {
      const data = await runScan(params);
      setResult(data);
    } catch (e) {
      setError(e.message || "scan failed");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="console-header">
        <h1>
          <svg
            className="logo"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 2.5 20 5.5V11c0 5-3.6 8.7-8 10.5C7.6 19.7 4 16 4 11V5.5Z" />
            <path d="M8.5 12 11 14.5 16 9" />
          </svg>
          tls-scanner
        </h1>
        <span className="subtitle">protocols · ciphers · certificate trust · CAA · HTTP headers · PQC readiness</span>
      </header>

      <ScanForm onScan={handleScan} loading={loading} />

      {error && <div className="error-banner">{error}</div>}

      {!result && !error && (
        <div className="empty-state">
          Enter a host or IP above and run a scan. Works against bare IPs, self-signed
          certs, and other endpoints a normal browser would refuse to talk to.
        </div>
      )}

      {result && (
        <>
          <div className="hero-row">
            <div className="hero-card">
              <GradeBadge grade={result.scoring.overall_grade} />
              <div>
                <div className="label">Overall grade &middot; {result.scoring.overall_score}/100</div>
                <div className="target">
                  {result.target.host}:{result.target.port}
                  {result.target.resolved_ip && result.target.resolved_ip !== result.target.host
                    ? ` (${result.target.resolved_ip})`
                    : ""}
                </div>
              </div>
            </div>
            <div className="hero-card">
              <PqcGauge score={result.scoring.pqc_readiness_score} label={result.scoring.pqc_readiness_label} />
            </div>
          </div>

          <div className="panel-grid">
            <ProtocolTable protocols={result.protocols} />
            <LegacyChecksPanel checks={result.legacy_checks} />
            <PqcGroupsPanel groups={result.key_exchange_groups} />
            <CipherList ciphers={result.ciphers} />
            <CertificatePanel cert={result.certificate} caa={result.dns_caa} />
            <HttpHeadersPanel
              headers={result.http_security_headers}
              score={result.scoring.http_headers_score}
              label={result.scoring.http_headers_label}
            />
            <FindingsList findings={result.scoring.findings} />
            <RawJsonPanel data={result} />
          </div>

          <div className="footer-note">
            scanned {new Date(result.scanned_at).toLocaleString()} in {result.duration_ms}ms
            &middot; scanner OpenSSL: {result.openssl_version}
          </div>
        </>
      )}
    </div>
  );
}
