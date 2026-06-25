import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import Sidebar, { type ChatSummary, type ContactSummary, type DiagnosticSummary } from './components/Sidebar';
import ChatView, { type ChatMessage } from './components/ChatView';
import IdentitySetup from './components/IdentitySetup';
import './App.css';

interface IdentityResponse {
  fingerprint: string;
  fingerprint_full: string;
  qr_data: string;
  invite_payload: string;
  generation: number;
  created_at: number;
  updated_at: number;
}

interface MessageResponse {
  message_id: string;
  status: string;
  timestamp: number;
  error?: string | null;
}

function App() {
  const [identity, setIdentity] = useState<IdentityResponse | null>(null);
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [diagnostics, setDiagnostics] = useState<DiagnosticSummary[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [clientRunning, setClientRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    void bootstrap();
  }, []);

  useEffect(() => {
    if (!activeChatId) {
      setMessages([]);
      return;
    }

    void loadMessages(activeChatId);
  }, [activeChatId]);

  useEffect(() => {
    if (!clientRunning) {
      return;
    }

    const interval = window.setInterval(() => {
      void loadContactsAndChats(activeChatId ?? undefined);
      void loadDiagnostics();
      if (activeChatId) {
        void loadMessages(activeChatId);
      }
    }, 2500);

    return () => window.clearInterval(interval);
  }, [clientRunning, activeChatId]);

  async function bootstrap() {
    try {
      const [storedIdentity, contactList, chatList, running, diagList] = await Promise.all([
        invoke<IdentityResponse | null>('get_identity'),
        invoke<ContactSummary[]>('get_contacts'),
        invoke<ChatSummary[]>('get_chats'),
        invoke<boolean>('start_client'),
        invoke<DiagnosticSummary[]>('get_diagnostics'),
      ]);

      setIdentity(storedIdentity);
      setContacts(contactList);
      setChats(chatList);
      setClientRunning(running);
      setDiagnostics(diagList);
      setStatusMessage(storedIdentity ? `Loaded stable profile ${storedIdentity.fingerprint}` : 'Ready for first-run identity setup');

      if (chatList.length > 0) {
        setActiveChatId(chatList[0].id);
      }
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to bootstrap app'));
    } finally {
      setLoading(false);
    }
  }

  async function loadContactsAndChats(preferredChatId?: string) {
    const [contactList, chatList] = await Promise.all([
      invoke<ContactSummary[]>('get_contacts'),
      invoke<ChatSummary[]>('get_chats'),
    ]);

    setContacts(contactList);
    setChats(chatList);

    const nextActive = preferredChatId
      ?? activeChatId
      ?? chatList[0]?.id
      ?? null;

    setActiveChatId(nextActive);
  }

  async function loadMessages(chatId: string) {
    try {
      const chatMessages = await invoke<ChatMessage[]>('get_messages', {
        chatId,
        limit: 200,
        offset: 0,
      });
      setMessages(chatMessages);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to load messages'));
      setMessages([]);
    }
  }

  async function loadDiagnostics() {
    try {
      const values = await invoke<DiagnosticSummary[]>('get_diagnostics');
      setDiagnostics(values);
    } catch {
      // Keep existing diagnostics if refresh fails.
    }
  }

  async function handleIdentityCreated(createdIdentity: IdentityResponse) {
    setIdentity(createdIdentity);
    setStatusMessage(`Identity ready at ${createdIdentity.fingerprint}`);
    setErrorMessage(null);
    await loadContactsAndChats();
    await loadDiagnostics();
  }

  async function handleResetIdentity() {
    try {
      await invoke<boolean>('reset_identity');
      setIdentity(null);
      setContacts([]);
      setChats([]);
      setMessages([]);
      setActiveChatId(null);
      setStatusMessage('Identity reset. A new install profile will be created on the next setup.');
      setErrorMessage(null);
      await loadDiagnostics();
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to reset identity'));
    }
  }

  async function handleAddContact(alias: string, fingerprint: string) {
    try {
      await invoke<ContactSummary>('add_contact', { alias, fingerprint });
      await loadContactsAndChats();
      await loadDiagnostics();
      setStatusMessage(`Saved contact ${alias}`);
      setErrorMessage(null);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to add contact'));
    }
  }

  async function handleUpdateContact(existingFingerprint: string, alias: string, newFingerprint: string) {
    try {
      await invoke<ContactSummary>('update_contact', {
        existingFingerprint,
        alias,
        newFingerprint,
      });
      await loadContactsAndChats(activeChatId ?? undefined);
      await loadDiagnostics();
      setStatusMessage(`Updated ${alias}`);
      setErrorMessage(null);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to update contact'));
    }
  }

  async function handleStartChat(contactFingerprint: string) {
    try {
      const chat = await invoke<ChatSummary>('create_chat', { contactFingerprint });
      await loadContactsAndChats(chat.id);
      await loadMessages(chat.id);
      setStatusMessage(`Opened chat for ${contactFingerprint}`);
      setErrorMessage(null);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to create chat'));
    }
  }

  async function handleRefreshChat(chatId: string) {
    try {
      const chat = await invoke<ChatSummary>('refresh_chat_destination', { chatId });
      await loadContactsAndChats(chat.id);
      await loadMessages(chat.id);
      await loadDiagnostics();
      setStatusMessage(`Chat destination refreshed to ${chat.contact_fingerprint}`);
      setErrorMessage(null);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to refresh chat destination'));
    }
  }

  async function handleSendMessage(content: string) {
    if (!activeChatId) {
      return;
    }

    try {
      const response = await invoke<MessageResponse>('send_message', {
        chatId: activeChatId,
        content,
      });

      await loadMessages(activeChatId);
      await loadDiagnostics();

      if (response.error) {
        setErrorMessage(response.error);
        setStatusMessage(null);
      } else {
        setStatusMessage(`Message persisted for delivery at ${new Date(response.timestamp * 1000).toLocaleTimeString()}`);
        setErrorMessage(null);
      }
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to send message'));
    }
  }

  const activeChat = chats.find((chat) => chat.id === activeChatId) ?? null;
  const matchedContact = activeChat
    ? contacts.find((contact) =>
      contact.fingerprint === activeChat.contact_fingerprint
      || contact.previous_fingerprints.includes(activeChat.contact_fingerprint))
    : null;
  const activeContact = matchedContact ?? null;
  const isActiveChatStale = Boolean(
    activeChat
    && activeContact
    && activeContact.fingerprint !== activeChat.contact_fingerprint,
  );

  if (loading) {
    return (
      <div className="app-loading">
        <div className="loading-spinner"></div>
        <p>Loading Shadowgram...</p>
      </div>
    );
  }

  return (
    <div className="app">
      {!identity ? (
        <IdentitySetup onIdentityCreated={handleIdentityCreated} />
      ) : (
        <div className="main-layout">
          <Sidebar
            identity={identity}
            chats={chats}
            contacts={contacts}
            diagnostics={diagnostics}
            activeChatId={activeChatId}
            onAddContact={handleAddContact}
            onUpdateContact={handleUpdateContact}
            onOpenChat={setActiveChatId}
            onStartChat={handleStartChat}
            onResetIdentity={handleResetIdentity}
          />
          <ChatView
            selectedChat={activeChat}
            selectedContact={activeContact}
            isDestinationStale={isActiveChatStale}
            messages={messages}
            onSendMessage={handleSendMessage}
            onRefreshChat={handleRefreshChat}
            statusMessage={statusMessage}
            errorMessage={errorMessage}
          />
        </div>
      )}

      <footer className="status-bar">
        <span className={`status-indicator ${clientRunning ? 'online' : 'offline'}`}></span>
        <span className="status-text">
          {clientRunning ? 'Profile loaded and transport listening' : 'Transport offline'}
        </span>
        <span className="status-detail">
          {identity ? `Stable fingerprint ${identity.fingerprint}` : 'Identity pending'}
        </span>
        <span className="version">v0.1.0-alpha</span>
      </footer>
    </div>
  );
}

function renderError(error: unknown, fallback: string): string {
  if (typeof error === 'string') {
    return error;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return fallback;
}

export default App;
