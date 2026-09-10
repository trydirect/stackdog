import { resolveApiPort } from './ports';
import { readEnv } from './env';

type WebSocketEvent = 
  | 'threat:detected'
  | 'alert:created'
  | 'alert:updated'
  | 'container:quarantined'
  | 'stats:updated';

type EventHandler = (data: any) => void;

export class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private eventHandlers: Map<WebSocketEvent, Set<EventHandler>> = new Map();
  private shouldReconnect = true;
  private failedInitialConnect = false;

  constructor(url?: string) {
    const env = readEnv();
    const apiPort = resolveApiPort(env);
    this.url = url || env.REACT_APP_WS_URL || `ws://localhost:${apiPort}/ws`;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        if (this.failedInitialConnect) {
          resolve();
          return;
        }
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleEvent(data.type, data.payload);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          if (!this.failedInitialConnect && this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          // WebSocket endpoint may be intentionally unavailable in some environments.
          // Fall back to REST-only mode after the first failed connect.
          this.failedInitialConnect = true;
          this.shouldReconnect = false;
          console.warn('WebSocket unavailable, running in polling mode');
          resolve();
        };
      } catch (error) {
        this.failedInitialConnect = true;
        this.shouldReconnect = false;
        resolve();
      }
    });
  }

  private scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      this.connect().catch(console.error);
    }, delay);
  }

  private handleEvent(type: string, payload: any) {
    const handlers = this.eventHandlers.get(type as WebSocketEvent);
    if (handlers) {
      handlers.forEach(handler => handler(payload));
    }
  }

  subscribe(event: WebSocketEvent, handler: EventHandler): () => void {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event)!.add(handler);

    // Return unsubscribe function
    return () => {
      this.eventHandlers.get(event)?.delete(handler);
    };
  }

  send(type: WebSocketEvent, payload: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    } else {
      console.warn('WebSocket not connected, message not sent');
    }
  }

  disconnect(): void {
    this.shouldReconnect = false;
    this.failedInitialConnect = false;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.eventHandlers.clear();
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}

export const webSocketService = new WebSocketService();
export default webSocketService;
