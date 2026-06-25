import { useMemo, useState } from 'react';

export interface ContactSummary {
  id: string;
  fingerprint: string;
  alias: string;
  trust_level: number;
  status: string;
  previous_fingerprints: string[];
  updated_at: number;
}

export interface ChatSummary {
  id: string;
  contact_fingerprint: string;
  created_at: number;
  immutable_history: boolean;
}

interface IdentitySummary {
  fingerprint: string;
  qr_data: string;
  generation: number;
  rotated_from: string[];
  created_at: number;
  updated_at: number;
}

interface SidebarProps {
  identity: IdentitySummary;
  chats: ChatSummary[];
  contacts: ContactSummary[];
  activeChatId: string | null;
  onAddContact: (alias: string, fingerprint: string) => Promise<void>;
  onUpdateContact: (existingFingerprint: string, alias: string, newFingerprint: string) => Promise<void>;
  onOpenChat: (chatId: string) => void;
  onStartChat: (contactFingerprint: string) => Promise<void>;
  onRotateIdentity: () => Promise<void>;
}

export default function Sidebar({
  identity,
  chats,
  contacts,
  activeChatId,
  onAddContact,
  onUpdateContact,
  onOpenChat,
  onStartChat,
  onRotateIdentity,
}: SidebarProps) {
  const [activeTab, setActiveTab] = useState<'chats' | 'contacts' | 'settings'>('chats');
  const [alias, setAlias] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [editingFingerprint, setEditingFingerprint] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

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

  function startEditing(contact: ContactSummary) {
    setEditingFingerprint(contact.fingerprint);
    setAlias(contact.alias);
    setFingerprint(contact.fingerprint);
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
        <p className="text-muted">Shared desktop + Android shell</p>
      </div>

      <nav className="sidebar-nav">
        <button className={`nav-item ${activeTab === 'chats' ? 'active' : ''}`} onClick={() => setActiveTab('chats')}>
          Chats
        </button>
        <button className={`nav-item ${activeTab === 'contacts' ? 'active' : ''}`} onClick={() => setActiveTab('contacts')}>
          Contacts
        </button>
        <button className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>
          Identity
        </button>
      </nav>

      <div className="sidebar-panel">
        {activeTab === 'chats' && (
          <div className="sidebar-list">
            {chats.length === 0 ? (
              <p className="text-muted">No chats yet. Add a contact and open a route.</p>
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
              <h3>{editingFingerprint ? 'Update Contact Fingerprint' : 'Add Contact'}</h3>
              <input
                className="input"
                value={alias}
                onChange={(event) => setAlias(event.target.value)}
                placeholder="Alias"
              />
              <input
                className="input"
                value={fingerprint}
                onChange={(event) => setFingerprint(event.target.value)}
                placeholder="Fingerprint"
              />
              <div className="button-row">
                <button className="btn btn-primary" onClick={() => void handleSubmitContact()} disabled={saving}>
                  {editingFingerprint ? 'Save Rotation' : 'Add Contact'}
                </button>
                {editingFingerprint && (
                  <button className="btn" onClick={resetForm}>
                    Cancel
                  </button>
                )}
              </div>
              <p className="text-muted text-sm">
                If a contact rotates their fingerprint, update it here. Old chats will stay immutable and can be refreshed.
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
                    <span className={`badge ${contact.status === 'active' ? 'badge-success' : 'badge-warning'}`}>
                      {contact.status}
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
                  <h3>Your Fingerprint</h3>
                  <p className="text-muted text-sm">Share this address so another device can reach you.</p>
                </div>
                <button className="btn btn-primary" onClick={() => void onRotateIdentity()}>
                  Rotate
                </button>
              </div>

              <div className="fingerprint-panel">
                <span className="text-muted text-sm">Current</span>
                <code>{identity.fingerprint}</code>
              </div>

              <div className="qr-placeholder card">
                <span className="text-muted text-sm">QR Payload</span>
                <code>{identity.qr_data}</code>
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

              <div className="history-block">
                <span className="text-muted text-sm">Previous fingerprints</span>
                {identity.rotated_from.length === 0 ? (
                  <p className="text-muted text-sm">No rotations yet.</p>
                ) : (
                  identity.rotated_from.map((value) => (
                    <code key={value}>{value}</code>
                  ))
                )}
              </div>
            </div>

            <div className="card">
              <p>Contacts: {contacts.length}</p>
              <p>Chats: {chats.length}</p>
              <p className="text-muted text-sm">
                Message history is append-only. Fingerprint changes create a new reachable address; stale chats need a refresh.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="sidebar-footer">
        <div className="security-status">
          <span className="status-dot"></span>
          <span>History locked against edits</span>
        </div>
      </div>
    </aside>
  );
}
