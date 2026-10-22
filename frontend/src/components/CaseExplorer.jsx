import React, { useState } from 'react';
import { FolderSearch, Search, AlertCircle, RefreshCw, FileCheck } from 'lucide-react';
import { fetchCaseReport } from '../api';
import ReportView from './ReportView';

const RECENT_CASES = [
  'CASE-LIVE-BINANCE-DEPOSIT-001',
  'CASE-LIVE-GENESIS-NO-PATH-002',
  'CASE-BINANCE-OFFLINE-001',
];

export default function CaseExplorer() {
  const [caseId, setCaseId] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLookup = async (idToLookup) => {
    const id = idToLookup || caseId;
    if (!id.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const data = await fetchCaseReport(id.trim());
      setReport(data);
      setCaseId(id.trim());
    } catch (err) {
      setError(err.message);
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <FolderSearch size={20} style={{ color: 'var(--accent-blue)' }} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>Retrieve Saved Forensic Case Report</h2>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
          Retrieve full chain-of-custody evidentiary case files and graph histories using their unique tracking ID.
        </p>

        {/* Quick Recent Case Pills */}
        <div style={{ marginBottom: '1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.375rem' }}>
            Recent On-Disk Investigation Records
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {RECENT_CASES.map((c) => (
              <button
                key={c}
                type="button"
                className="btn btn-outline"
                style={{ padding: '0.375rem 0.625rem', fontSize: '0.75rem' }}
                onClick={() => handleLookup(c)}
              >
                <FileCheck size={12} />
                <span>{c}</span>
              </button>
            ))}
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLookup();
          }}
          style={{ display: 'flex', gap: '0.75rem' }}
        >
          <input
            type="text"
            className="form-input font-mono"
            placeholder="Enter Case ID (e.g. CASE-LIVE-BINANCE-DEPOSIT-001)"
            value={caseId}
            onChange={(e) => setCaseId(e.target.value)}
            disabled={loading}
          />
          <button type="submit" className="btn btn-primary" disabled={loading || !caseId.trim()} style={{ minWidth: '130px' }}>
            {loading ? <RefreshCw size={16} className="animate-spin" /> : <Search size={16} />}
            <span>Lookup</span>
          </button>
        </form>

        {error && (
          <div className="alert alert-danger" style={{ marginTop: '1rem' }}>
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Render Retrieved Report */}
      {report && <ReportView report={report} />}
    </div>
  );
}
