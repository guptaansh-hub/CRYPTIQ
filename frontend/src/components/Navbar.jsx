import React from 'react';
import { Shield, Search, FolderSearch, Database, Activity } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, health }) {
  return (
    <header
      style={{
        background: 'rgba(17, 24, 39, 0.95)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid var(--border-color)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      <div
        className="container"
        style={{
          height: '64px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-cyan) 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'white',
              boxShadow: '0 0 15px rgba(59, 130, 246, 0.4)',
            }}
          >
            <Shield size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '1.125rem', fontWeight: 800, letterSpacing: '-0.025em' }}>
                CRYPTIQ
              </span>
              <span className="badge badge-blue" style={{ fontSize: '0.65rem' }}>
                SIH26183
              </span>
            </div>
            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Fraud-Linked Cryptocurrency Exchange Identification
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className={`btn ${activeTab === 'investigate' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.5rem 0.875rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('investigate')}
          >
            <Search size={15} />
            <span>Investigate</span>
          </button>
          <button
            className={`btn ${activeTab === 'cases' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.5rem 0.875rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('cases')}
          >
            <FolderSearch size={15} />
            <span>Case Explorer</span>
          </button>
          <button
            className={`btn ${activeTab === 'entities' ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '0.5rem 0.875rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('entities')}
          >
            <Database size={15} />
            <span>Verified Disclosures</span>
          </button>
        </nav>

        {/* Backend Status Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.375rem',
              fontSize: '0.75rem',
              padding: '0.375rem 0.625rem',
              borderRadius: '9999px',
              background: health?.status === 'healthy' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
              border: `1px solid ${health?.status === 'healthy' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}`,
              color: health?.status === 'healthy' ? '#34d399' : '#fb7185',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: health?.status === 'healthy' ? '#10b981' : '#f43f5e',
                boxShadow: health?.status === 'healthy' ? '0 0 8px #10b981' : 'none',
              }}
            />
            <span>{health?.status === 'healthy' ? 'FastAPI Online' : 'FastAPI Offline'}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
