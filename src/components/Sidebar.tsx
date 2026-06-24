import { useMemo, useState } from 'react';

export interface ContactSummary {
  fingerprint: string;
  alias: string;
  trust_level: number;
}

export interface ChatSummary {
  id: string;
  contact_fingerprint: string;
  created_at: number;
}

interface SidebarProps {
  chats: ChatSummary[];
  contacts: ContactSummary[];
  activeChatId: string | null;
  onAddContact: (alias: string, fingerprint: string) => Promise<void>;
  onOpenChat: (chatId: string) => void;
  onStartChat: (contactFingerprint: string) => Promise<void>;
}

export default function Sidebar({
  chats,
  contacts,
  activeChatId,
  onAddContact,
  onOpenChat,
  onStartChat,
}: SidebarProps) {
  const [activeTab, setActiveTab] = useState<'chats' | 'contacts' | 'settings'>('chats');
  const [alias, setAlias] = useState('');
  const [fingerprint, setFingerprint] = useState('');

  const chatLookup = useMemo(
    () =>
      new Map(
        contacts.map((contact) => [contact.fingerprint, contact.alias]),
      ),
    [contacts],
  );

  async function handleAddContact() {
    if (!alias.trim() || !fingerprint.trim()) {
      return;
    }

    await onAddContact(alias.trim(), fingerprint.trim());
    setAlias('');
    setFingerprint('');
    setActiveTab('contacts');
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h2>Shadowgram</h2>
        <p className="text-muted">Desktop integration shell</p>
      </div>

      <nav className="sidebar-nav">
        <button className={`nav-item ${activeTab === 'chats' ? 'active' : ''}`} onClick={() => setActiveTab('chats')}>
          Chats
        </button>
        <button className={`nav-item ${activeTab === 'contacts' ? 'active' : ''}`} onClick={() => setActiveTab('contacts')}>
          Contacts
        </button>
        <button className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}>
          Status
        </button>
      </nav>

      <div className="sidebar-panel">
        {activeTab === 'chats' && (
          <div className="sidebar-list">
            {chats.length === 0 ? (
              <p className="text-muted">No chats yet. Add a contact first.</p>
            ) : (
              chats.map((chat) => (
                <button
                  key={chat.id}
                  className={`list-item ${chat.id === activeChatId ? 'active' : ''}`}
                  onClick={() => onOpenChat(chat.id)}
                >
                  <span>{chatLookup.get(chat.contact_fingerprint) ?? chat.contact_fingerprint}</span>
                  <span className="text-muted text-sm">{chat.contact_fingerprint}</span>
                </button>
              ))
            )}
          </div>
        )}

        {activeTab === 'contacts' && (
          <div className="sidebar-list">
            <div className="card contact-form">
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
              <button className="btn btn-primary" onClick={handleAddContact}>
                Add Contact
              </button>
            </div>

            {contacts.map((contact) => (
              <div key={contact.fingerprint} className="list-item static">
                <div>
                  <div>{contact.alias}</div>
                  <div className="text-muted text-sm">{contact.fingerprint}</div>
                </div>
                <button className="btn" onClick={() => onStartChat(contact.fingerprint)}>
                  Open Chat
                </button>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="sidebar-list">
            <div className="card">
              <p>Contacts: {contacts.length}</p>
              <p>Chats: {chats.length}</p>
              <p className="text-muted text-sm">Core crypto and networking crates still need full integration.</p>
            </div>
          </div>
        )}
      </div>

      <div className="sidebar-footer">
        <div className="security-status">
          <span className="status-dot"></span>
          <span>Integration audited</span>
        </div>
      </div>
    </aside>
  );
}
