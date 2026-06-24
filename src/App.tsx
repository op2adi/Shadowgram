import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import Sidebar, { type ChatSummary, type ContactSummary } from './components/Sidebar';
import ChatView, { type ChatMessage } from './components/ChatView';
import IdentitySetup from './components/IdentitySetup';
import './App.css';

interface IdentityResponse {
  fingerprint: string;
  qr_data: string;
}

function App() {
  const [identity, setIdentity] = useState<IdentityResponse | null>(null);
  const [contacts, setContacts] = useState<ContactSummary[]>([]);
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [clientRunning, setClientRunning] = useState(false);

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
      console.error('Failed to bootstrap app:', error);
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
        limit: 100,
        offset: 0,
      });
      setMessages(chatMessages);
    } catch (error) {
      console.error('Failed to load messages:', error);
      setMessages([]);
    }
  }

  async function handleIdentityCreated(createdIdentity: IdentityResponse) {
    setIdentity(createdIdentity);
    await loadContactsAndChats();
  }

  async function handleAddContact(alias: string, fingerprint: string) {
    await invoke<boolean>('add_contact', { alias, fingerprint });
    await loadContactsAndChats();
  }

  async function handleStartChat(contactFingerprint: string) {
    const chat = await invoke<ChatSummary>('create_chat', { contactFingerprint });
    await loadContactsAndChats(chat.id);
    await loadMessages(chat.id);
  }

  async function handleSendMessage(content: string) {
    if (!activeChatId) {
      return;
    }

    await invoke('send_message', {
      chatId: activeChatId,
      content,
    });

    await loadMessages(activeChatId);
  }

  const activeChat = chats.find((chat) => chat.id === activeChatId) ?? null;
  const activeContact = activeChat
    ? contacts.find((contact) => contact.fingerprint === activeChat.contact_fingerprint) ?? null
    : null;

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
            chats={chats}
            contacts={contacts}
            activeChatId={activeChatId}
            onAddContact={handleAddContact}
            onOpenChat={setActiveChatId}
            onStartChat={handleStartChat}
          />
          <ChatView
            selectedChat={activeChat}
            selectedContact={activeContact}
            messages={messages}
            onSendMessage={handleSendMessage}
          />
        </div>
      )}

      <footer className="status-bar">
        <span className={`status-indicator ${clientRunning ? 'online' : 'offline'}`}></span>
        <span className="status-text">
          {clientRunning ? 'Desktop shell ready' : 'Disconnected'}
        </span>
        <span className="version">v0.1.0-alpha</span>
      </footer>
    </div>
  );
}

export default App;
