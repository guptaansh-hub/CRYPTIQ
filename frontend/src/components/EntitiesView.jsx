import React, { useEffect, useState } from 'react';
import { Database, ShieldCheck, AlertCircle, ExternalLink, RefreshCw } from 'lucide-react';
import { fetchEntities } from '../api';

export default function EntitiesView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchEntities();
      setData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--accent-blue)', margin: '0 auto 0.75rem' }} />
        <p style={{ color: 'var(--text-secondary)' }}>Loading verified attribution registries...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger">
        <AlertCircle size={20} />
        <div>
          <strong>Failed to load entity statistics:</strong> {error}
        </div>
      </div>
    );
  }

  if (!data) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Metric Cards Header */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
        <div className="card">
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Verified Disclosures
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.25rem' }}>
            {data.total_records.toLocaleString()}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
            Cryptographically indexed
          </span>
        </div>

        <div className="card">
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Exchange Reserve Wallets
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#34d399', marginTop: '0.25rem' }}>
            {data.by_category?.exchange || 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Binance ({data.by_actor?.binance || 0}) • Bybit ({data.by_actor?.bybit || 0})
          </span>
        </div>

        <div className="card">
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Flagged Scam / Phishing Feeds
          </span>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fb7185', marginTop: '0.25rem' }}>
            {data.by_category?.scam || 0}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            EtherScamDB curated abuse records
          </span>
        </div>
      </div>

      {/* TagPacks Table */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Database size={20} style={{ color: 'var(--accent-blue)' }} />
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600 }}>Authenticated TagPack Disclosures</h3>
          </div>
          <button className="btn btn-outline" onClick={loadData} style={{ padding: '0.375rem 0.625rem' }}>
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '0.8125rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.625rem' }}>TagPack Title</th>
                <th style={{ padding: '0.625rem' }}>Actor</th>
                <th style={{ padding: '0.625rem' }}>Category</th>
                <th style={{ padding: '0.625rem' }}>Confidence</th>
                <th style={{ padding: '0.625rem' }}>Records</th>
                <th style={{ padding: '0.625rem' }}>Cluster Definer</th>
                <th style={{ padding: '0.625rem' }}>Official Provenance</th>
              </tr>
            </thead>
            <tbody>
              {data.tagpacks?.map((tp, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '0.625rem', fontWeight: 600 }}>{tp.title}</td>
                  <td style={{ padding: '0.625rem' }}>
                    <span className="badge badge-slate">{tp.actor.toUpperCase()}</span>
                  </td>
                  <td style={{ padding: '0.625rem' }}>
                    <span className={`badge ${tp.category === 'exchange' ? 'badge-emerald' : 'badge-rose'}`}>
                      {tp.category}
                    </span>
                  </td>
                  <td style={{ padding: '0.625rem' }}>
                    <span className="badge badge-blue">{tp.confidence}</span>
                  </td>
                  <td style={{ padding: '0.625rem' }}>{tp.records_count}</td>
                  <td style={{ padding: '0.625rem' }}>
                    {tp.is_cluster_definer ? 'Yes (Proof-of-Reserves)' : 'No'}
                  </td>
                  <td style={{ padding: '0.625rem' }}>
                    {tp.source ? (
                      <a
                        href={tp.source}
                        target="_blank"
                        rel="noreferrer"
                        style={{ color: 'var(--accent-cyan)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
                      >
                        <span>View Source</span>
                        <ExternalLink size={12} />
                      </a>
                    ) : (
                      'N/A'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
