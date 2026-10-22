import React, { useState } from 'react';
import { Search, Globe, ShieldAlert, Cpu, HelpCircle, AlertTriangle } from 'lucide-react';

const SAMPLES = [
  {
    name: 'Binance Cold Vault (Direct Attribution)',
    address: '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo',
    note: 'Known cold reserve vault in official Binance disclosures',
    networkFetch: false,
  },
  {
    name: 'Real Deposit to Binance (Live On-Chain)',
    address: 'bc1p8y2uvfyu7azz4zkl45cza9cyc63q0g3hqgdes5wmzpr2rjq4axas80uelt',
    note: 'Taproot wallet with verified deposit into Binance vault',
    networkFetch: true,
  },
  {
    name: 'Genesis Unspent (No Exchange Path)',
    address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    note: 'Satoshi block 0 address (no outgoing transactions)',
    networkFetch: true,
  },
  {
    name: 'EtherScamDB Phishing (Prior Abuse Flag)',
    address: '0xD0cC2B24980CBCCA47EF755Da88B220a82291407',
    note: 'Flagged phishing address in verified abuse feed',
    networkFetch: false,
  },
];

export default function InvestigationForm({ onSubmit, loading }) {
  const [address, setAddress] = useState('');
  const [caseId, setCaseId] = useState('');
  const [maxHops, setMaxHops] = useState(4);
  const [taintModel, setTaintModel] = useState('haircut');
  const [enableNetwork, setEnableNetwork] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!address.trim()) return;
    onSubmit({
      address: address.trim(),
      case_id: caseId.trim() || undefined,
      max_hops: maxHops,
      taint_model: taintModel,
      enable_network_fetching: enableNetwork,
    });
  };

  const handleSelectSample = (sample) => {
    setAddress(sample.address);
    setEnableNetwork(sample.networkFetch);
    setCaseId(`CASE-SAMPLE-${Date.now().toString().slice(-4)}`);
  };

  // Quick address format detection for feedback
  const detectFormat = (addr) => {
    const clean = addr.trim();
    if (!clean) return null;
    if (clean.startsWith('1')) return { type: 'BTC P2PKH (Legacy Base58)', color: 'blue' };
    if (clean.startsWith('3')) return { type: 'BTC P2SH (Script Base58)', color: 'blue' };
    if (clean.toLowerCase().startsWith('bc1q')) return { type: 'BTC Native SegWit (Bech32)', color: 'cyan' };
    if (clean.toLowerCase().startsWith('bc1p')) return { type: 'BTC Taproot (Bech32m)', color: 'emerald' };
    if (clean.startsWith('0x') && clean.length === 42) return { type: 'ETH Hex (Account)', color: 'amber' };
    return { type: 'Custom / Unclassified Format', color: 'slate' };
  };

  const formatInfo = detectFormat(address);

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
        <Search size={20} style={{ color: 'var(--accent-blue)' }} />
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>Forensic Case Intake & Address Analysis</h2>
      </div>

      {/* Preset Samples */}
      <div style={{ marginBottom: '1.25rem' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, display: 'block', marginBottom: '0.5rem' }}>
          Quick Benchmark Cases (Verified Provenance)
        </span>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {SAMPLES.map((s, idx) => (
            <button
              key={idx}
              type="button"
              className="btn btn-outline"
              style={{ padding: '0.375rem 0.75rem', fontSize: '0.75rem' }}
              onClick={() => handleSelectSample(s)}
            >
              <span>{s.name}</span>
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Address Input */}
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
            <label style={{ fontSize: '0.875rem', fontWeight: 500 }}>
              Suspect Cryptocurrency Address <span style={{ color: 'var(--accent-rose)' }}>*</span>
            </label>
            {formatInfo && (
              <span className={`badge badge-${formatInfo.color}`}>
                {formatInfo.type}
              </span>
            )}
          </div>
          <input
            type="text"
            className="form-input font-mono"
            placeholder="e.g. bc1p..., 34xp..., 1A1z..., or 0x..."
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            required
            disabled={loading}
          />
        </div>

        {/* Configuration Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.375rem' }}>
              Custom Case Identifier (Optional)
            </label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g. CASE-SIH-2026-001"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              disabled={loading}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.375rem' }}>
              Maximum Forward Hops ({maxHops})
            </label>
            <input
              type="range"
              min="1"
              max="10"
              value={maxHops}
              onChange={(e) => setMaxHops(Number(e.target.value))}
              disabled={loading}
              style={{ width: '100%', marginTop: '0.5rem' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.375rem' }}>
              Taint Accounting Model
            </label>
            <select
              className="form-select"
              value={taintModel}
              onChange={(e) => setTaintModel(e.target.value)}
              disabled={loading}
            >
              <option value="haircut">Haircut (Proportional Inflow Blending)</option>
              <option value="fifo">FIFO (First-In, First-Out Sequential)</option>
            </select>
          </div>
        </div>

        {/* Explicit Network Fetching Toggle */}
        <div
          style={{
            padding: '0.875rem 1rem',
            background: enableNetwork ? 'rgba(59, 130, 246, 0.08)' : 'var(--bg-secondary)',
            border: `1px solid ${enableNetwork ? 'var(--accent-blue)' : 'var(--border-color)'}`,
            borderRadius: '0.5rem',
            marginBottom: '1.25rem',
            transition: 'all 0.2s',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
              <Globe size={18} style={{ color: enableNetwork ? 'var(--accent-blue)' : 'var(--text-muted)' }} />
              <div>
                <label
                  htmlFor="net-toggle"
                  style={{
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    color: enableNetwork ? 'var(--text-primary)' : 'var(--text-secondary)',
                  }}
                >
                  Enable Live Blockchain Fetching (Esplora REST API)
                </label>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                  {enableNetwork
                    ? 'Active: Queries Blockstream Esplora and populates transaction graph with live/cached on-chain records.'
                    : 'Disabled by default: Investigates locally with verified TagPacks and pre-loaded graph records.'}
                </p>
              </div>
            </div>

            <label style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
              <input
                id="net-toggle"
                type="checkbox"
                checked={enableNetwork}
                onChange={(e) => setEnableNetwork(e.target.checked)}
                disabled={loading}
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span
                style={{
                  position: 'absolute',
                  cursor: 'pointer',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  backgroundColor: enableNetwork ? 'var(--accent-blue)' : '#475569',
                  transition: '0.3s',
                  borderRadius: '24px',
                }}
              >
                <span
                  style={{
                    position: 'absolute',
                    content: '""',
                    height: '18px',
                    width: '18px',
                    left: enableNetwork ? '22px' : '3px',
                    bottom: '3px',
                    backgroundColor: 'white',
                    transition: '0.3s',
                    borderRadius: '50%',
                  }}
                />
              </span>
            </label>
          </div>
        </div>

        {/* Submit Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading || !address.trim()}
            style={{ minWidth: '180px' }}
          >
            {loading ? (
              <>
                <Cpu size={16} className="animate-spin" />
                <span>Tracing Flow...</span>
              </>
            ) : (
              <>
                <Search size={16} />
                <span>Run Investigation</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
