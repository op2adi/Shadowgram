import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import Sidebar, { type ChatSummary, type ContactSummary } from './components/Sidebar';
import ChatView, { type ChatMessage } from './components/ChatView';
import IdentitySetup from './components/IdentitySetup';
import './App.css';

interface IdentityResponse {
  fingerprint: string;
  qr_data: string;
  generation: number;
  rotated_from: string[];
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

  async function bootstrap() {
    try {
      const [storedIdentity, contactList, chatList, running] = await Promise.all([
        invoke<IdentityResponse | null>('get_identity'),
        invoke<ContactSummary[]>('get_contacts'),
        invoke<ChatSummary[]>('get_chats'),
        invoke<boolean>('start_client'),
      ]);

      setIdentity(storedIdentity);
      setContacts(contactList);
      setChats(chatList);
      setClientRunning(running);

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

  async function handleIdentityCreated(createdIdentity: IdentityResponse) {
    setIdentity(createdIdentity);
    setStatusMessage(`Identity ready at ${createdIdentity.fingerprint}`);
    setErrorMessage(null);
    await loadContactsAndChats();
  }

  async function handleRotateIdentity() {
    try {
      const rotated = await invoke<IdentityResponse>('rotate_identity');
      setIdentity(rotated);
      setStatusMessage(`Your public fingerprint rotated to ${rotated.fingerprint}`);
      setErrorMessage(null);
    } catch (error) {
      setErrorMessage(renderError(error, 'Failed to rotate identity'));
    }
  }

  async function handleAddContact(alias: string, fingerprint: string) {
    try {
      await invoke<ContactSummary>('add_contact', { alias, fingerprint });
      await loadContactsAndChats();
      setStatusMessage(`Saved ${alias} at ${fingerprint}`);
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
      setStatusMessage(`Updated ${alias} to ${newFingerprint}`);
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

      if (response.error) {
        setErrorMessage(response.error);
        setStatusMessage(null);
      } else {
        setStatusMessage(`Message sealed for delivery at ${new Date(response.timestamp * 1000).toLocaleTimeString()}`);
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
            activeChatId={activeChatId}
            onAddContact={handleAddContact}
            onUpdateContact={handleUpdateContact}
            onOpenChat={setActiveChatId}
            onStartChat={handleStartChat}
            onRotateIdentity={handleRotateIdentity}
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
          {clientRunning ? 'Shell running on desktop/mobile target' : 'Disconnected'}
        </span>
        <span className="status-detail">
          {identity ? `Fingerprint generation ${identity.generation}` : 'Identity pending'}
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
