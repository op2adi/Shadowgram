import { useMemo, useState } from 'react';

export interface ContactSummary {
  id: string;
  fingerprint: string;
  alias: string;
  trust_level: number;
  status: string;
  invite_payload: string;
  previous_fingerprints: string[];
  endpoint?: {
    host: string;
    port: number;
  } | null;
  updated_at: number;
}

export interface ChatSummary {
  id: string;
  contact_fingerprint: string;
  created_at: number;
  immutable_history: boolean;
}

export interface DiagnosticSummary {
  level: string;
  stage: string;
  message: string;
  timestamp: number;
}

interface IdentitySummary {
  fingerprint: string;
  fingerprint_full: string;
  qr_data: string;
  invite_payload: string;
  generation: number;
  created_at: number;
  updated_at: number;
}

interface SidebarProps {
  identity: IdentitySummary;
  chats: ChatSummary[];
  contacts: ContactSummary[];
  diagnostics: DiagnosticSummary[];
  activeChatId: string | null;
  onAddContact: (alias: string, fingerprint: string) => Promise<void>;
  onUpdateContact: (existingFingerprint: string, alias: string, newFingerprint: string) => Promise<void>;
  onOpenChat: (chatId: string) => void;
  onStartChat: (contactFingerprint: string) => Promise<void>;
  onResetIdentity: () => Promise<void>;
}

export default function Sidebar({
  identity,
  chats,
  contacts,
  diagnostics,
  activeChatId,
  onAddContact,
  onUpdateContact,
  onOpenChat,
  onStartChat,
  onResetIdentity,
}: SidebarProps) {
  const [activeTab, setActiveTab] = useState<'chats' | 'contacts' | 'settings'>('chats');
  const [alias, setAlias] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [editingFingerprint, setEditingFingerprint] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [copyMessage, setCopyMessage] = useState<string | null>(null);

  const contactLookup = useMemo(
    () => {
      const entries = new Map<string, ContactSummary>();
      for (const contact of contacts) {
        entries.set(contact.fingerprint, contact);
        for (const previousFingerprint of contact.previous_fingerprints) {
          entries.set(previousFingerprint, contact);
        }
      }
      return entries;
    },
    [contacts],
  );

  async function handleSubmitContact() {
    if (!alias.trim() || !fingerprint.trim()) {
      return;
    }

    setSaving(true);
    try {
      if (editingFingerprint) {
        await onUpdateContact(editingFingerprint, alias.trim(), fingerprint.trim());
      } else {
        await onAddContact(alias.trim(), fingerprint.trim());
      }
      resetForm();
      setActiveTab('contacts');
    } finally {
      setSaving(false);
    }
  }

  async function copyInvite() {
    await navigator.clipboard.writeText(identity.invite_payload);
    setCopyMessage('Invite copied');
    window.setTimeout(() => setCopyMessage(null), 1500);
  }

  async function copyFingerprint() {
    await navigator.clipboard.writeText(identity.fingerprint);
    setCopyMessage('Fingerprint copied');
    window.setTimeout(() => setCopyMessage(null), 1500);
  }

  function startEditing(contact: ContactSummary) {
    setEditingFingerprint(contact.fingerprint);
    setAlias(contact.alias);
    setFingerprint(contact.invite_payload || contact.fingerprint);
    setActiveTab('contacts');
  }

  function resetForm() {
    setAlias('');
    setFingerprint('');
    setEditingFingerprint(null);
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h2>Shadowgram</h2>
        <p className="text-muted">Stable profile shell for desktop and Android</p>
      </div>

      <nav className="sidebar-nav">
        <button className={`nav-item ${activeTab === 'chats' ? 'active' : ''}`} onClick={() => setActiveTab('chats')}>
          Chats
        </button>
        <button className={`nav-item ${activeTab === 'contacts' ? 'active' : ''}`} onClick={() => setActiveTab('contacts')}>
          Add Contact
        </button>
        <button className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>
          My Identity
        </button>
      </nav>

      <div className="sidebar-panel">
        {activeTab === 'chats' && (
          <div className="sidebar-list">
            {chats.length === 0 ? (
              <p className="text-muted">No chats yet. Share your invite, add a contact, then open a route.</p>
            ) : (
              chats.map((chat) => {
                const contact = contactLookup.get(chat.contact_fingerprint);
                const isStale = Boolean(contact && contact.fingerprint !== chat.contact_fingerprint);
                return (
                  <button
                    key={chat.id}
                    className={`list-item ${chat.id === activeChatId ? 'active' : ''}`}
                    onClick={() => onOpenChat(chat.id)}
                  >
                    <div className="list-item-main">
                      <span>{contact?.alias ?? chat.contact_fingerprint}</span>
                      <span className="text-muted text-sm">{chat.contact_fingerprint}</span>
                    </div>
                    <div className="list-item-meta">
                      {contact?.endpoint && <span className="badge badge-success">Routable</span>}
                      {!contact?.endpoint && <span className="badge badge-warning">Invite only</span>}
                      {isStale && <span className="badge badge-warning">Stale route</span>}
                      {chat.immutable_history && <span className="badge">Append-only</span>}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        )}

        {activeTab === 'contacts' && (
          <div className="sidebar-list">
            <div className="card contact-form">
              <h3>{editingFingerprint ? 'Update Contact Invite' : 'Add Contact From Invite'}</h3>
              <input
                className="input"
                value={alias}
                onChange={(event) => setAlias(event.target.value)}
                placeholder="Alias"
              />
              <textarea
                className="input"
                value={fingerprint}
                onChange={(event) => setFingerprint(event.target.value)}
                placeholder="Paste fingerprint or full invite payload"
                rows={5}
              />
              <div className="button-row">
                <button className="btn btn-primary" onClick={() => void handleSubmitContact()} disabled={saving}>
                  {editingFingerprint ? 'Save Contact' : 'Import Contact'}
                </button>
                {editingFingerprint && (
                  <button className="btn" onClick={resetForm}>
                    Cancel
                  </button>
                )}
              </div>
              <p className="text-muted text-sm">
                Paste the full invite payload for routable delivery. A bare fingerprint saves the contact but cannot route messages.
              </p>
            </div>

            {contacts.map((contact) => (
              <div key={contact.id} className="list-item static contact-card">
                <div className="contact-card-copy">
                  <div className="contact-card-header">
                    <div>
                      <div>{contact.alias}</div>
                      <div className="text-muted text-sm">{contact.fingerprint}</div>
                    </div>
                    <span className={`badge ${contact.endpoint ? 'badge-success' : 'badge-warning'}`}>
                      {contact.endpoint ? `${contact.endpoint.host}:${contact.endpoint.port}` : contact.status}
                    </span>
                  </div>
                  {contact.previous_fingerprints.length > 0 && (
                    <div className="history-block">
                      <span className="text-muted text-sm">Previous fingerprints</span>
                      {contact.previous_fingerprints.map((previous) => (
                        <code key={previous}>{previous}</code>
                      ))}
                    </div>
                  )}
                </div>
                <div className="button-column">
                  <button className="btn" onClick={() => void onStartChat(contact.fingerprint)}>
                    Open Chat
                  </button>
                  <button className="btn" onClick={() => startEditing(contact)}>
                    Update
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="sidebar-list">
            <div className="card settings-card">
              <div className="settings-header">
                <div>
                  <h3>My Identity</h3>
                  <p className="text-muted text-sm">This stable fingerprint persists across launches until you explicitly reset it.</p>
                </div>
                <button className="btn btn-danger" onClick={() => void onResetIdentity()}>
                  Reset Identity
                </button>
              </div>

              <div className="fingerprint-panel">
                <span className="text-muted text-sm">Shareable fingerprint</span>
                <code>{identity.fingerprint}</code>
              </div>

              <div className="fingerprint-panel">
                <span className="text-muted text-sm">Full fingerprint</span>
                <code>{identity.fingerprint_full}</code>
              </div>

              <div className="button-row">
                <button className="btn btn-primary" onClick={() => void copyInvite()}>
                  Copy Invite
                </button>
                <button className="btn" onClick={() => void copyFingerprint()}>
                  Copy Fingerprint
                </button>
                {copyMessage && <span className="text-muted text-sm">{copyMessage}</span>}
              </div>

              <div className="qr-placeholder card">
                <span className="text-muted text-sm">Invite Payload / QR Data</span>
                <code>{identity.invite_payload}</code>
              </div>

              <div className="metadata-grid">
                <div>
                  <span className="text-muted text-sm">Generation</span>
                  <strong>{identity.generation}</strong>
                </div>
                <div>
                  <span className="text-muted text-sm">Updated</span>
                  <strong>{new Date(identity.updated_at * 1000).toLocaleString()}</strong>
                </div>
              </div>
            </div>

            <div className="card">
              <h3>Diagnostics</h3>
              <div className="history-block">
                {diagnostics.slice(-8).reverse().map((entry) => (
                  <div key={`${entry.timestamp}-${entry.stage}`}>
                    <strong>{entry.level.toUpperCase()}</strong> {entry.stage}
                    <div className="text-muted text-sm">{entry.message}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="sidebar-footer">
        <div className="security-status">
          <span className="status-dot"></span>
          <span>Persistent profile loaded</span>
        </div>
      </div>
    </aside>
  );
}
