import React, { useEffect, useState } from 'react';
import Navbar from './components/Navbar';
import InvestigationForm from './components/InvestigationForm';
import ReportView from './components/ReportView';
import CaseExplorer from './components/CaseExplorer';
import EntitiesView from './components/EntitiesView';
import { fetchHealth, investigateAddress } from './api';
import { Shield, AlertCircle, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('investigate');
  const [health, setHealth] = useState(null);
  const [currentReport, setCurrentReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch((err) => {
        console.warn('Backend health check error:', err);
        setHealth({ status: 'error' });
      });
  }, []);

  const handleInvestigate = async (payload) => {
    setLoading(true);
    setError(null);
    try {
      const data = await investigateAddress(payload);
      setCurrentReport(data);
    } catch (err) {
      setError(err.message || 'Investigation request failed.');
      setCurrentReport(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} health={health} />

      <main className="container" style={{ flex: 1, padding: '2rem 1.5rem' }}>
        {/* Error notification if investigation fails */}
        {error && (
          <div className="alert alert-danger" style={{ marginBottom: '1.5rem' }}>
            <AlertCircle size={20} style={{ flexShrink: 0 }} />
            <div>
              <strong>Investigation Error:</strong> {error}
            </div>
          </div>
        )}

        {/* Tab 1: Investigation View */}
        {activeTab === 'investigate' && (
          <div>
            <InvestigationForm onSubmit={handleInvestigate} loading={loading} />
            {currentReport && <ReportView report={currentReport} />}
          </div>
        )}

        {/* Tab 2: Saved Case Explorer View */}
        {activeTab === 'cases' && <CaseExplorer />}

        {/* Tab 3: Verified Entities & TagPacks View */}
        {activeTab === 'entities' && <EntitiesView />}
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--border-color)',
          padding: '1.5rem 0',
          background: 'var(--bg-secondary)',
          color: 'var(--text-muted)',
          fontSize: '0.75rem',
        }}
      >
        <div className="container" style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <p>
              <strong>CRYPTIQ</strong> • Smart India Hackathon 2026 (SIH26183)
            </p>
            <p style={{ marginTop: '0.25rem' }}>
              Real-Time Identification of Fraud-Linked Cryptocurrency Exchanges from Victim-Reported Suspect Addresses.
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <p>
              Verified External Provenance: GraphSense Service Disclosures & EtherScamDB
            </p>
            <p style={{ marginTop: '0.25rem' }}>
              Offline AML Baseline Model Isolated • Integer Satoshi Conservation
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
