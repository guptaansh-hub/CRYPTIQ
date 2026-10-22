import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  FileText,
  Download,
  ExternalLink,
  Layers,
  ArrowRight,
  Database,
  Info,
  CheckCircle2,
  Copy,
} from 'lucide-react';
import GraphVisualizer from './GraphVisualizer';

export default function ReportView({ report }) {
  if (!report) return null;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
  };

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.case_id || 'CRYPTIQ-REPORT'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    // Generate clean markdown from report data
    const lines = [
      `# CRYPTIQ Forensic Investigation Report: ${report.case_id}`,
      ``,
      `> **Evidentiary Boundary (SIH26183):** Identifying an exchange attribution (direct or via transaction connection)`,
      `> indicates that funds reached or are held by exchange infrastructure. It is **NOT** proof that the exchange`,
      `> entity itself is fraudulent, complicit, or criminal.`,
      ``,
      `## 1. Case Metadata & Address Validation`,
      `- **Case ID:** \`${report.case_id}\``,
      `- **Suspect Address:** \`${report.suspect_address}\``,
      `- **Network:** \`${report.currency}\``,
      `- **Format:** \`${report.address_validation?.format || 'unknown'}\``,
      `- **Cryptographic Validity:** \`${report.address_validation?.is_valid ? 'VALID' : 'INVALID'}\``,
      ``,
    ];

    if (report.direct_exchange_attribution) {
      const d = report.direct_exchange_attribution;
      lines.push(
        `## 2. Direct Exchange Attribution Findings`,
        `- **Exchange:** **${d.exchange_name.toUpperCase()}**`,
        `- **Confidence:** \`${d.attribution_confidence}\``,
        `- **Wallet Label:** ${d.label}`,
        `- **Reserve Wallet:** ${d.is_reserve_wallet ? 'Yes' : 'No'}`,
        `- **Source Disclosure:** ${d.source_disclosure}`,
        ``
      );
    }

    if (report.exchange_connections && report.exchange_connections.length > 0) {
      lines.push(
        `## 3. Downstream Exchange Connections`,
        `| Exchange | Confidence | Destination Wallet | Min Hops | Taint Received |`,
        `|---|---|---|---|---|`
      );
      report.exchange_connections.forEach((c) => {
        lines.push(
          `| **${c.exchange_name.toUpperCase()}** | \`${c.attribution_confidence}\` | \`${c.destination_wallet}\` | ${c.min_hop_distance} | ${c.total_taint_received.toFixed(6)} ${c.taint_currency} |`
        );
      });
      lines.push(``);
    }

    lines.push(
      `## 4. Methodological & Model Boundaries`,
      `- **AML Risk Note:** ${report.aml_transaction_risk_note}`,
      `- **Disclaimer:** ${report.disclaimer}`
    );

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.case_id || 'CRYPTIQ-REPORT'}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const gStatus = report.transaction_graph_status || {};
  const netMeta = report.network_fetch_metadata;
  const direct = report.direct_exchange_attribution;
  const connections = report.exchange_connections || [];
  const priors = report.suspect_prior_abuse_flags || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Evidentiary Boundary Alert */}
      <div className="alert alert-warning">
        <Info size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong style={{ display: 'block', marginBottom: '0.25rem' }}>
            Evidentiary Boundary (SIH26183 Mandate)
          </strong>
          <span style={{ fontSize: '0.8125rem', opacity: 0.9 }}>
            Identifying an exchange attribution (direct or via transaction connection) establishes that funds reached or are
            held by verified exchange infrastructure. It is <strong>NOT</strong> proof that the exchange entity itself is
            fraudulent, criminal, or complicit.
          </span>
        </div>
      </div>

      {/* Case Header Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
              <span className="badge badge-blue">Case File</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }} className="font-mono">
                {report.case_id}
              </h2>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Investigation UTC: {report.created_at_utc}
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-secondary" onClick={handleDownloadJSON}>
              <Download size={14} />
              <span>Export JSON</span>
            </button>
            <button className="btn btn-secondary" onClick={handleDownloadMarkdown}>
              <FileText size={14} />
              <span>Export Markdown</span>
            </button>
          </div>
        </div>

        {/* Address & Network Metadata */}
        <div
          style={{
            marginTop: '1.25rem',
            padding: '1rem',
            background: 'var(--bg-secondary)',
            borderRadius: '0.5rem',
            border: '1px solid var(--border-color)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '1rem',
          }}
        >
          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Target Suspect Address
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
              <span className="font-mono" style={{ fontSize: '0.875rem', wordBreak: 'break-all' }}>
                {report.suspect_address}
              </span>
              <button
                className="btn btn-outline"
                style={{ padding: '0.25rem', borderRadius: '4px' }}
                onClick={() => handleCopy(report.suspect_address)}
                title="Copy Address"
              >
                <Copy size={12} />
              </button>
            </div>
          </div>

          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Network & Classification
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
              <span className="badge badge-emerald">
                {report.currency} • {report.address_validation?.format}
              </span>
              {report.address_validation?.is_valid && (
                <span className="badge badge-blue">
                  <CheckCircle2 size={12} /> Cryptographically Valid
                </span>
              )}
            </div>
          </div>

          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              On-Chain Ingestion Status
            </span>
            <div style={{ marginTop: '0.25rem' }}>
              <span className={`badge ${gStatus.graph_loaded ? 'badge-blue' : 'badge-slate'}`}>
                {gStatus.transactions_indexed || 0} Transactions Indexed
              </span>
            </div>
          </div>
        </div>

        {/* Partial History Notice if has_more is true */}
        {gStatus.has_more && (
          <div className="alert alert-warning" style={{ marginTop: '1rem' }}>
            <AlertTriangle size={18} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.8125rem' }}>
              <strong>Partial History Detected (`has_more = True`):</strong> Address history contains additional
              transactions beyond the 25-transaction page limit. Analysis reflects the most recent 25 transactions and is
              bounded.
            </div>
          </div>
        )}
      </div>

      {/* Direct Exchange Attribution Card */}
      {direct && (
        <div
          className="card"
          style={{
            borderLeft: '4px solid var(--accent-emerald)',
            background: 'linear-gradient(135deg, rgba(6, 78, 59, 0.2) 0%, var(--bg-card) 100%)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.75rem' }}>
            <ShieldCheck size={24} style={{ color: 'var(--accent-emerald)' }} />
            <div>
              <span className="badge badge-emerald">Direct Attribution</span>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: '0.25rem' }}>
                {direct.exchange_name.toUpperCase()} (Verified Exchange Infrastructure)
              </h3>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', fontSize: '0.875rem' }}>
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', display: 'block' }}>Wallet Label</span>
              <strong>{direct.label}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', display: 'block' }}>Confidence Tier</span>
              <span className="badge badge-emerald">{direct.attribution_confidence} (Official Disclosure)</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', display: 'block' }}>Cold Storage / Reserve</span>
              <span>{direct.is_reserve_wallet ? 'Yes (Proof-of-Reserves Cluster Definer)' : 'No'}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', display: 'block' }}>Source Disclosure</span>
              <a
                href={direct.source_disclosure}
                target="_blank"
                rel="noreferrer"
                style={{ color: 'var(--accent-cyan)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
              >
                <span>Official Proof-of-Reserves</span>
                <ExternalLink size={12} />
              </a>
            </div>
          </div>

          <p style={{ marginTop: '0.75rem', fontSize: '0.8125rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
            {direct.evidentiary_note}
          </p>
        </div>
      )}

      {/* Prior Abuse Flags Card */}
      {priors.length > 0 && (
        <div className="card" style={{ borderLeft: '4px solid var(--accent-rose)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <AlertTriangle size={20} style={{ color: 'var(--accent-rose)' }} />
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Prior Abuse Registry Records ({priors.length})</h3>
          </div>
          <table style={{ width: '100%', fontSize: '0.8125rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.5rem' }}>Feed Source</th>
                <th style={{ padding: '0.5rem' }}>Category / Abuse</th>
                <th style={{ padding: '0.5rem' }}>Confidence</th>
                <th style={{ padding: '0.5rem' }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {priors.map((p, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '0.5rem' }}>{p.source}</td>
                  <td style={{ padding: '0.5rem' }}><span className="badge badge-rose">{p.abuse}</span></td>
                  <td style={{ padding: '0.5rem' }}>{p.confidence}</td>
                  <td style={{ padding: '0.5rem' }}>{p.label}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Interactive Flow Graph Canvas */}
      <GraphVisualizer
        suspectAddress={report.suspect_address}
        directAttribution={direct}
        exchangeConnections={connections}
        discoveredPaths={report.discovered_exchange_paths || []}
      />

      {/* Downstream Exchange Connections Table */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Layers size={20} style={{ color: 'var(--accent-cyan)' }} />
          <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
            Downstream Exchange Connections ({connections.length})
          </h3>
        </div>

        {connections.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', fontSize: '0.8125rem', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.5rem' }}>Exchange Entity</th>
                  <th style={{ padding: '0.5rem' }}>Attribution Confidence</th>
                  <th style={{ padding: '0.5rem' }}>Destination Wallet</th>
                  <th style={{ padding: '0.5rem' }}>Min Hops</th>
                  <th style={{ padding: '0.5rem' }}>Total Taint Flow</th>
                  <th style={{ padding: '0.5rem' }}>Reserve Status</th>
                </tr>
              </thead>
              <tbody>
                {connections.map((c, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <td style={{ padding: '0.5rem' }}>
                      <strong style={{ color: 'var(--text-primary)' }}>{c.exchange_name.toUpperCase()}</strong>
                    </td>
                    <td style={{ padding: '0.5rem' }}>
                      <span className="badge badge-emerald">{c.attribution_confidence}</span>
                    </td>
                    <td style={{ padding: '0.5rem' }}>
                      <span className="font-mono">{c.destination_wallet}</span>
                    </td>
                    <td style={{ padding: '0.5rem' }}>{c.min_hop_distance} hop(s)</td>
                    <td style={{ padding: '0.5rem' }}>
                      <strong>{c.total_taint_received.toFixed(6)} {c.taint_currency}</strong>
                    </td>
                    <td style={{ padding: '0.5rem' }}>
                      {c.is_reserve_wallet ? (
                        <span className="badge badge-emerald">Proof-of-Reserves</span>
                      ) : (
                        'Standard'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            _No downstream transaction paths connecting to verified exchange reserve wallets within the search depth._
          </p>
        )}
      </div>

      {/* Model & Methodological Boundaries */}
      <div className="card" style={{ background: 'var(--bg-secondary)', fontSize: '0.8125rem' }}>
        <h4 style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          Forensic & Machine Learning Boundaries
        </h4>
        <ul style={{ paddingLeft: '1.25rem', color: 'var(--text-muted)', lineHeight: '1.6' }}>
          <li>
            <strong>AML Model Boundary:</strong> {report.aml_transaction_risk_note}
          </li>
          <li style={{ marginTop: '0.25rem' }}>
            <strong>Attribution Provenance:</strong> {report.disclaimer}
          </li>
        </ul>
      </div>
    </div>
  );
}
