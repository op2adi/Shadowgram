import { useState } from 'react';
import type { ChatSummary, ContactSummary } from './Sidebar';

export interface ChatMessage {
  id: string;
  content: string;
  direction: string;
  timestamp: number;
  status: string;
}

interface ChatViewProps {
  selectedChat: ChatSummary | null;
  selectedContact: ContactSummary | null;
  messages: ChatMessage[];
  onSendMessage: (content: string) => Promise<void>;
}

export default function ChatView({
  selectedChat,
  selectedContact,
  messages,
  onSendMessage,
}: ChatViewProps) {
  const [newMessage, setNewMessage] = useState('');

  async function sendMessage() {
    if (!newMessage.trim() || !selectedChat) {
      return;
    }

    await onSendMessage(newMessage.trim());
    setNewMessage('');
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
          <p className="text-muted">The desktop shell now supports local contact, chat, and message state.</p>
        </div>
      ) : (
        <>
          <header className="chat-header">
            <div className="chat-info">
              <h3>{selectedContact?.alias ?? selectedChat.contact_fingerprint}</h3>
              <span className="text-muted text-sm">{selectedChat.contact_fingerprint}</span>
            </div>
          </header>

          <div className="messages-container">
            {messages.length === 0 ? (
              <p className="text-muted">No messages yet for this chat.</p>
            ) : (
              messages.map((message) => (
                <div
                  key={message.id}
                  className={`message ${message.direction === 'outgoing' ? 'message-outgoing' : 'message-incoming'}`}
                >
                  <div className="message-bubble">{message.content}</div>
                  <span className="message-time">
                    {new Date(message.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>

          <div className="message-input">
            <textarea
              value={newMessage}
              onChange={(event) => setNewMessage(event.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a local message..."
              rows={2}
              className="input"
            />
            <button className="btn btn-primary send-button" onClick={() => void sendMessage()} disabled={!newMessage.trim()}>
              Send
            </button>
          </div>
        </>
      )}
    </main>
  );
}
