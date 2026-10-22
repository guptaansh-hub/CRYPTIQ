import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, Shield, ArrowRight, ExternalLink } from 'lucide-react';

export default function GraphVisualizer({
  suspectAddress,
  directAttribution,
  exchangeConnections = [],
  discoveredPaths = [],
}) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selectedElement, setSelectedElement] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Build Cytoscape elements from real data
    const elements = [];
    const nodeSet = new Set();
    const edgeSet = new Set();

    // Case 1: Direct Exchange Attribution (1 focal node)
    if (directAttribution) {
      elements.push({
        data: {
          id: suspectAddress,
          label: `${directAttribution.exchange_name.toUpperCase()}\n(Direct Reserve Vault)`,
          type: 'exchange',
          address: suspectAddress,
          details: directAttribution,
        },
      });
    }
    // Case 2: Multi-Hop Discovered Exchange Paths
    else if (discoveredPaths && discoveredPaths.length > 0) {
      // Add suspect node
      nodeSet.add(suspectAddress);
      elements.push({
        data: {
          id: suspectAddress,
          label: `SUSPECT\n${suspectAddress.slice(0, 6)}...${suspectAddress.slice(-4)}`,
          type: 'suspect',
          address: suspectAddress,
        },
      });

      // Add edges and nodes from actual path steps
      discoveredPaths.forEach((path) => {
        path.steps.forEach((step) => {
          const from = step.from_address;
          const to = step.to_address;

          if (!nodeSet.has(from)) {
            nodeSet.add(from);
            elements.push({
              data: {
                id: from,
                label: `Hop ${step.hop_number - 1}\n${from.slice(0, 6)}...${from.slice(-4)}`,
                type: 'intermediary',
                address: from,
              },
            });
          }

          if (!nodeSet.has(to)) {
            nodeSet.add(to);
            const isTerminalExchange = step.attribution_actor !== null;
            elements.push({
              data: {
                id: to,
                label: isTerminalExchange
                  ? `${step.attribution_actor.toUpperCase()}\n${to.slice(0, 6)}...${to.slice(-4)}`
                  : `Hop ${step.hop_number}\n${to.slice(0, 6)}...${to.slice(-4)}`,
                type: isTerminalExchange ? 'exchange' : 'intermediary',
                address: to,
                actor: step.attribution_actor,
                labelDesc: step.attribution_label,
              },
            });
          }

          const edgeId = `${from}->${to}-${step.txid}`;
          if (!edgeSet.has(edgeId)) {
            edgeSet.add(edgeId);
            elements.push({
              data: {
                id: edgeId,
                source: from,
                target: to,
                label: `${step.taint_amount.toFixed(6)} BTC`,
                txid: step.txid,
                value: step.value,
                taint_ratio: step.taint_ratio,
                taint_amount: step.taint_amount,
              },
            });
          }
        });
      });
    }
    // Case 3: We have exchange connections but no step-by-step path payload
    else if (exchangeConnections.length > 0) {
      nodeSet.add(suspectAddress);
      elements.push({
        data: {
          id: suspectAddress,
          label: `SUSPECT\n${suspectAddress.slice(0, 6)}...${suspectAddress.slice(-4)}`,
          type: 'suspect',
          address: suspectAddress,
        },
      });

      exchangeConnections.forEach((conn) => {
        const dest = conn.destination_wallet;
        if (!nodeSet.has(dest)) {
          nodeSet.add(dest);
          elements.push({
            data: {
              id: dest,
              label: `${conn.exchange_name.toUpperCase()}\n${dest.slice(0, 6)}...${dest.slice(-4)}`,
              type: 'exchange',
              address: dest,
              actor: conn.exchange_name,
            },
          });

          elements.push({
            data: {
              id: `edge-${suspectAddress}-${dest}`,
              source: suspectAddress,
              target: dest,
              label: `${conn.total_taint_received.toFixed(6)} ${conn.taint_currency} (${conn.min_hop_distance} hops)`,
              min_hops: conn.min_hop_distance,
            },
          });
        }
      });
    }

    if (elements.length === 0) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      return;
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#f8fafc',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '11px',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'width': '95px',
            'height': '95px',
            'border-width': '2px',
            'border-color': '#475569',
            'background-color': '#1e293b',
          },
        },
        {
          selector: 'node[type = "suspect"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#f43f5e',
            'border-width': '3px',
          },
        },
        {
          selector: 'node[type = "intermediary"]',
          style: {
            'background-color': '#0f172a',
            'border-color': '#38bdf8',
          },
        },
        {
          selector: 'node[type = "exchange"]',
          style: {
            'background-color': '#064e3b',
            'border-color': '#10b981',
            'border-width': '3px',
            'width': '105px',
            'height': '105px',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#64748b',
            'target-arrow-color': '#94a3b8',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'color': '#94a3b8',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '9px',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#fbbf24',
            'border-width': '4px',
            'line-color': '#fbbf24',
            'target-arrow-color': '#fbbf24',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.35,
      },
    });

    cy.on('tap', 'node', (evt) => {
      setSelectedElement({ type: 'node', data: evt.target.data() });
    });

    cy.on('tap', 'edge', (evt) => {
      setSelectedElement({ type: 'edge', data: evt.target.data() });
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedElement(null);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [suspectAddress, directAttribution, exchangeConnections, discoveredPaths]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit();

  const hasData =
    Boolean(directAttribution) ||
    exchangeConnections.length > 0 ||
    discoveredPaths.length > 0;

  if (!hasData) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem' }}>
        <Shield size={40} style={{ color: 'var(--text-muted)', margin: '0 auto 1rem' }} />
        <h4 style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          No On-Chain Flow Paths to Display
        </h4>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', maxWidth: '480px', margin: '0 auto' }}>
          No transaction paths connecting to verified exchange reserve wallets were found.
          CRYPTIQ enforces strict evidentiary standards and never invents synthetic graph edges.
        </p>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: '1rem', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Forensic Flow Graph (Cytoscape.js)</h3>
          <span className="badge badge-blue">Directed BFS DAG</span>
        </div>
        <div style={{ display: 'flex', gap: '0.375rem' }}>
          <button className="btn btn-outline" style={{ padding: '0.375rem 0.625rem' }} onClick={handleZoomIn} title="Zoom In">
            <ZoomIn size={16} />
          </button>
          <button className="btn btn-outline" style={{ padding: '0.375rem 0.625rem' }} onClick={handleZoomOut} title="Zoom Out">
            <ZoomOut size={16} />
          </button>
          <button className="btn btn-outline" style={{ padding: '0.375rem 0.625rem' }} onClick={handleFit} title="Fit View">
            <Maximize2 size={16} />
          </button>
        </div>
      </div>

      {/* Cytoscape Canvas */}
      <div
        ref={containerRef}
        style={{
          width: '100%',
          height: '420px',
          background: 'rgba(15, 23, 42, 0.8)',
          borderRadius: '0.5rem',
          border: '1px solid var(--border-color)',
        }}
      />

      {/* Selected Element Inspector */}
      {selectedElement && (
        <div
          style={{
            marginTop: '0.75rem',
            padding: '0.75rem 1rem',
            background: 'var(--bg-secondary)',
            borderRadius: '0.5rem',
            border: '1px solid var(--border-color)',
            fontSize: '0.8125rem',
          }}
        >
          {selectedElement.type === 'node' ? (
            <div>
              <span className="badge badge-slate" style={{ marginRight: '0.5rem' }}>
                Node: {selectedElement.data.type?.toUpperCase()}
              </span>
              <span className="font-mono" style={{ wordBreak: 'break-all' }}>
                {selectedElement.data.address}
              </span>
              {selectedElement.data.actor && (
                <div style={{ marginTop: '0.25rem', color: '#34d399' }}>
                  Exchange Entity: <strong>{selectedElement.data.actor.toUpperCase()}</strong> ({selectedElement.data.labelDesc || 'Verified Wallet'})
                </div>
              )}
            </div>
          ) : (
            <div>
              <span className="badge badge-blue" style={{ marginRight: '0.5rem' }}>
                Transaction Edge
              </span>
              {selectedElement.data.txid && (
                <span className="font-mono" style={{ wordBreak: 'break-all' }}>
                  TxID: {selectedElement.data.txid}
                </span>
              )}
              {selectedElement.data.taint_amount !== undefined && (
                <div style={{ marginTop: '0.25rem' }}>
                  Taint Transferred: <strong>{selectedElement.data.taint_amount} BTC</strong> (Ratio: {(selectedElement.data.taint_ratio * 100).toFixed(2)}%)
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
