import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

interface IdentityResponse {
  fingerprint: string;
  qr_data: string;
}

interface IdentitySetupProps {
  onIdentityCreated: (identity: IdentityResponse) => void;
}

export default function IdentitySetup({ onIdentityCreated }: IdentitySetupProps) {
  const [creating, setCreating] = useState(false);
  const [identity, setIdentity] = useState<IdentityResponse | null>(null);

  async function handleCreateIdentity() {
    setCreating(true);
    try {
      const result = await invoke<IdentityResponse>('create_identity');
      setIdentity(result);
      onIdentityCreated(result);
    } catch (error) {
      console.error('Failed to create identity:', error);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="identity-setup">
      <div className="identity-card card">
        <div className="identity-header">
          <svg className="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <h1>Shadowgram</h1>
          <p className="text-muted">Local-first privacy messenger shell</p>
        </div>

        {!identity ? (
          <div className="identity-create">
            <div className="identity-info">
              <h2>Create Your Private Identity</h2>
              <ul className="feature-list">
                <li>No phone number required</li>
                <li>No email address required</li>
                <li>Local identity bootstrap</li>
                <li>Ready for contact and chat flows</li>
              </ul>
            </div>

            <button
              className="btn btn-primary btn-large"
              onClick={handleCreateIdentity}
              disabled={creating}
            >
              {creating ? 'Generating Identity...' : 'Create Identity'}
            </button>

            <p className="text-muted text-sm">
              This desktop shell stores the generated fingerprint in memory only.
            </p>
          </div>
        ) : (
          <div className="identity-created">
            <div className="success-icon">OK</div>
            <h2>Identity Created</h2>
            <div className="fingerprint-display card">
              <span className="text-muted">Fingerprint</span>
              <code>{identity.fingerprint}</code>
            </div>
            <div className="qr-placeholder card">
              <span className="text-muted">QR Payload</span>
              <code>{identity.qr_data}</code>
            </div>
            <p className="text-success">
              The app can now store contacts and open local chat sessions.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
