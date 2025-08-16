import React, { useState, useEffect } from 'react';

// Header component
const Header = () => (
  <header className="header">
    <div className="header-container">
      <img 
        src="/logo.jpeg" 
        alt="PAVE Logo" 
        className="logo"
        onError={(e) => {
          e.target.src = "/logo.svg";
          e.target.onerror = null;
        }}
      />
      <div>
        <h1 className="header-title">pave</h1>
        <p className="header-subtitle">Admin Dashboard</p>
      </div>
    </div>
  </header>
);

// Metric card component
const MetricCard = ({ value, subtitle, icon }) => (
  <div className="metric-card">
    {icon && <div className="metric-icon">{icon}</div>}
    <span className="metric-value">{value}</span>
    <span className="metric-subtitle">{subtitle}</span>
  </div>
);


// Metrics grid component
const MetricsGrid = ({ activeIssuers }) => (
  <div className="metrics-grid">
    <MetricCard 
      value="125,823"
      subtitle="verifications made today"
      icon="✅"
    />
    <MetricCard 
      value={activeIssuers}
      subtitle="currently active issuers"
      icon="🏢"
    />
  </div>
);

// Issuer row component
const IssuerRow = ({ issuer, onToggleStatus }) => {
  const statusBadge = issuer.status === 'valid' ? 
    <span className="status-badge status-active">
      <span className="status-dot status-dot-active"></span>
      Active
    </span> :
    <span className="status-badge status-suspended">
      <span className="status-dot status-dot-suspended"></span>
      Suspended
    </span>;

  const actionButton = issuer.status === 'valid' ?
    <button 
      onClick={() => onToggleStatus(issuer.id)}
      className="btn btn-suspend"
    >
      <span className="btn-icon">⏸️</span>
      Suspend
    </button> :
    <button 
      onClick={() => onToggleStatus(issuer.id)}
      className="btn btn-activate"
    >
      <span className="btn-icon">▶️</span>
      Activate
    </button>;

  return (
    <tr>
      <td>{issuer.name}</td>
      <td>
        <a href={issuer.url} className="table-link">{issuer.url}</a>
      </td>
      <td>{statusBadge}</td>
      <td className="success-rate">{issuer.successRate}</td>
      <td className="methods">{issuer.methods.join(', ')}</td>
      <td>{actionButton}</td>
    </tr>
  );
};

// Issuer table component
const IssuerTable = ({ issuers, onToggleStatus }) => (
  <div className="table-container">
    <div className="table-header">
      <span className="table-icon">📊</span>
      <h2 className="table-title">Issuer Analytics</h2>
    </div>
    <div className="table-wrapper">
      <table className="table">
        <thead>
          <tr>
            <th>Issuer</th>
            <th>URL</th>
            <th>Status</th>
            <th>Success Rate</th>
            <th>Methods</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {issuers.map(issuer => (
            <IssuerRow key={issuer.id} issuer={issuer} onToggleStatus={onToggleStatus} />
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

// Add issuer form component
const AddIssuerForm = ({ onAddIssuer }) => {
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    methods: []
  });

  const availableMethods = ['face', 'passport', "driver's license", 'credit card', 'other'];

  const handleMethodChange = (method) => {
    setFormData(prev => ({
      ...prev,
      methods: prev.methods.includes(method)
        ? prev.methods.filter(m => m !== method)
        : [...prev.methods, method]
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (formData.name && formData.url && formData.methods.length > 0) {
      onAddIssuer({
        ...formData,
        id: Date.now(), // Simple ID generation
        status: 'valid',
        successRate: '100%'
      });
      setFormData({ name: '', url: '', methods: [] });
    }
  };

  return (
    <div className="form-container">
      <div className="form-header">
        <span className="form-icon">➕</span>
        <h3 className="form-title">Add New Issuer</h3>
      </div>
      <form onSubmit={handleSubmit} className="form">
        <div className="form-group">
          <label className="form-label">Issuer Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            className="form-input"
            placeholder="Enter issuer name"
            required
          />
        </div>
        <div className="form-group">
          <label className="form-label">API URL</label>
          <input
            type="url"
            value={formData.url}
            onChange={(e) => setFormData(prev => ({ ...prev, url: e.target.value }))}
            className="form-input"
            placeholder="https://example.com/api"
            required
          />
        </div>
        <div className="form-group">
          <label className="form-label">Allowed Methods</label>
          <div className="checkbox-group">
            {availableMethods.map(method => (
              <label key={method} className="checkbox-item">
                <input
                  type="checkbox"
                  checked={formData.methods.includes(method)}
                  onChange={() => handleMethodChange(method)}
                  className="checkbox-input"
                />
                <span className="checkbox-label">{method}</span>
              </label>
            ))}
          </div>
        </div>
        <button type="submit" className="btn-primary">
          <span className="btn-primary-icon">➕</span>
          Add Issuer
        </button>
      </form>
    </div>
  );
};

// Main dashboard component
export default function Dashboard() {
  const [issuers, setIssuers] = useState([
    {
      id: 1,
      name: "FastAge Verification",
      url: "https://api.fastage.com",
      status: "valid",
      successRate: "98.5%",
      methods: ["face", "passport"]
    },
    {
      id: 2,
      name: "SecureID Corp",
      url: "https://secureid.example.com",
      status: "valid",
      successRate: "95.2%",
      methods: ["driver's license", "passport"]
    },
    {
      id: 3,
      name: "TrustVerify",
      url: "https://trust-verify.net",
      status: "invalid",
      successRate: "0%",
      methods: ["face", "credit card"]
    },
    {
      id: 4,
      name: "IdentityCheck Plus",
      url: "https://idcheck.plus",
      status: "valid",
      successRate: "97.8%",
      methods: ["passport", "other"]
    },
    {
      id: 5,
      name: "VerifyMe Solutions",
      url: "https://verifyme.solutions",
      status: "valid",
      successRate: "96.1%",
      methods: ["face", "driver's license", "passport"]
    },
    {
      id: 6,
      name: "AgeGuard Systems",
      url: "https://ageguard.systems",
      status: "invalid",
      successRate: "0%",
      methods: ["credit card", "other"]
    },
    {
      id: 7,
      name: "ProofPoint Verify",
      url: "https://proofpoint-verify.com",
      status: "valid",
      successRate: "99.1%",
      methods: ["face", "passport", "driver's license"]
    },
    {
      id: 8,
      name: "AuthentiCheck",
      url: "https://authenticheck.io",
      status: "valid",
      successRate: "94.7%",
      methods: ["passport", "credit card"]
    },
    {
      id: 9,
      name: "ValidateID Pro",
      url: "https://validateid.pro",
      status: "invalid",
      successRate: "0%",
      methods: ["face", "other"]
    },
    {
      id: 10,
      name: "CertifyAge Network",
      url: "https://certifyage.network",
      status: "valid",
      successRate: "92.3%",
      methods: ["driver's license", "passport", "credit card"]
    }
  ]);

  // API functions for backend communication
  const fetchIssuers = async () => {
    try {
      const response = await fetch('http://localhost:8002/admin/issuers');
      if (response.ok) {
        const data = await response.json();
        // Transform backend data to match our format
        const transformedIssuers = data.issuers?.map(issuer => ({
          id: issuer.issuer_id || issuer.kid || issuer.name,
          name: issuer.name || issuer.kid,
          url: issuer.jwks_uri || issuer.jwks_url || 'N/A',
          status: issuer.status === 'active' ? 'valid' : 'invalid',
          successRate: '98%',
          methods: issuer.allowed_methods || ['face', 'passport']
        })) || [];
        setIssuers(transformedIssuers);
      }
    } catch (error) {
      console.log('Using mock data - backend not available:', error);
    }
  };

  const toggleIssuerStatus = async (issuerId) => {
    const issuer = issuers.find(i => i.id === issuerId);
    const newStatus = issuer.status === 'valid' ? 'suspended' : 'active';
    
    try {
      const response = await fetch(`http://localhost:8002/admin/issuers/${issuerId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      
      if (response.ok) {
        // Update local state
        setIssuers(prev => prev.map(i => 
          i.id === issuerId 
            ? { ...i, status: newStatus === 'active' ? 'valid' : 'invalid' }
            : i
        ));
      }
    } catch (error) {
      console.log('Backend not available, updating locally:', error);
      // Fallback to local state update
      setIssuers(prev => prev.map(i => 
        i.id === issuerId 
          ? { ...i, status: i.status === 'valid' ? 'invalid' : 'valid' }
          : i
      ));
    }
  };

  const addIssuer = async (newIssuer) => {
    try {
      const response = await fetch('http://localhost:8002/admin/issuers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kid: newIssuer.name.toLowerCase().replace(/\s+/g, '-'),
          name: newIssuer.name,
          jwks_uri: newIssuer.url,
          status: 'active'
        })
      });
      
      if (response.ok) {
        fetchIssuers(); // Refresh the list
      }
    } catch (error) {
      console.log('Backend not available, adding locally:', error);
      // Fallback to local state update
      setIssuers(prev => [...prev, newIssuer]);
    }
  };

  // Load issuers on component mount
  useEffect(() => {
    fetchIssuers();
  }, []);

  const activeIssuersCount = issuers.filter(issuer => issuer.status === 'valid').length;

  return (
    <div>
      <Header />
      
      <div className="main-content">
        <div className="welcome-section">
          <h1 className="welcome-title">Welcome to pave Dashboard</h1>
          <p className="welcome-description">Monitor and manage your issuer network with real-time analytics</p>
        </div>
        
        <MetricsGrid activeIssuers={activeIssuersCount} />
        <IssuerTable issuers={issuers} onToggleStatus={toggleIssuerStatus} />
        <AddIssuerForm onAddIssuer={addIssuer} />
      </div>
    </div>
  );
}