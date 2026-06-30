import { useState } from 'react';
import type { ChatSummary, ContactSummary } from './Sidebar';

export interface ChatMessage {
  id: string;
  content: string;
  direction: string;
  timestamp: number;
  status: string;
  error?: string | null;
  destination_fingerprint: string;
  immutable: boolean;
  delivered_at?: number | null;
  retry_count: number;
}

interface ChatViewProps {
  selectedChat: ChatSummary | null;
  selectedContact: ContactSummary | null;
  isDestinationStale: boolean;
  messages: ChatMessage[];
  isLoadingMessages: boolean;
  onSendMessage: (content: string) => Promise<boolean>;
  onRefreshChat: (chatId: string) => Promise<void>;
  statusMessage: string | null;
  errorMessage: string | null;
}

export default function ChatView({
  selectedChat,
  selectedContact,
  isDestinationStale,
  messages,
  isLoadingMessages,
  onSendMessage,
  onRefreshChat,
  statusMessage,
  errorMessage,
}: ChatViewProps) {
  const [newMessage, setNewMessage] = useState('');
  const [sending, setSending] = useState(false);

  async function sendMessage() {
    if (!newMessage.trim() || !selectedChat || sending) {
      return;
    }

    setSending(true);
    try {
      const sent = await onSendMessage(newMessage.trim());
      // Only clear the compose box if the send actually succeeded, so a failed
      // message isn't silently lost.
      if (sent) {
        setNewMessage('');
      }
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  }

  return (
    <main className="chat-view">
      {!selectedChat ? (
        <div className="no-chat-selected">
          <h2>Select a chat to start messaging</h2>
          <p className="text-muted">Your current fingerprint is the address you share. Contact rotations create new addresses that stale chats cannot reach until refreshed.</p>
        </div>
      ) : (
        <>
          <header className="chat-header">
            <div className="chat-info">
              <h3>{selectedContact?.alias ?? selectedChat.contact_fingerprint}</h3>
              <span className="text-muted text-sm">Current route: {selectedChat.contact_fingerprint}</span>
            </div>
            {selectedChat.immutable_history && <span className="badge">Append-only history</span>}
          </header>

          {(statusMessage || errorMessage || isDestinationStale) && (
            <div className="chat-alerts">
              {isDestinationStale && selectedContact && (
                <div className="alert alert-warning">
                  <div>
                    <strong>Destination fingerprint changed.</strong>
                    <p>
                      This chat still points to {selectedChat.contact_fingerprint}, but {selectedContact.alias} now uses {selectedContact.fingerprint}.
                    </p>
                  </div>
                  <button className="btn" onClick={() => void onRefreshChat(selectedChat.id)}>
                    Refresh Route
                  </button>
                </div>
              )}
              {statusMessage && <div className="alert alert-success">{statusMessage}</div>}
              {errorMessage && <div className="alert alert-error">{errorMessage}</div>}
            </div>
          )}

          <div className="messages-container">
            {isLoadingMessages && messages.length === 0 ? (
              <p className="text-muted">Loading messages…</p>
            ) : messages.length === 0 ? (
              <p className="text-muted">No messages yet for this chat.</p>
            ) : (
              messages.map((message) => (
                <div
                  key={message.id}
                  className={`message ${message.direction === 'outgoing' ? 'message-outgoing' : message.direction === 'incoming' ? 'message-incoming' : 'message-system'}`}
                >
                  <div className="message-bubble">
                    <p>{message.content}</p>
                    <div className="message-meta">
                      <span className="message-time">
                        {new Date(message.timestamp * 1000).toLocaleTimeString()}
                      </span>
                      <span className={`badge ${message.status === 'failed' ? 'badge-error' : message.status === 'refreshed' ? 'badge-warning' : 'badge-success'}`}>
                        {message.status}
                      </span>
                      {message.immutable && <span className="badge">Locked</span>}
                    </div>
                    {message.direction !== 'system' && (
                      <span className="text-muted text-sm">Destination: {message.destination_fingerprint}</span>
                    )}
                    {message.error && <p className="message-error">{message.error}</p>}
                    {message.retry_count > 0 && (
                      <p className="text-muted text-sm">Retries: {message.retry_count}</p>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="message-input">
            <textarea
              value={newMessage}
              onChange={(event) => setNewMessage(event.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type an append-only message..."
              rows={2}
              className="input"
            />
            <button className="btn btn-primary send-button" onClick={() => void sendMessage()} disabled={!newMessage.trim() || sending}>
              {sending ? 'Sending…' : 'Send'}
            </button>
          </div>
        </>
      )}
    </main>
  );
}
