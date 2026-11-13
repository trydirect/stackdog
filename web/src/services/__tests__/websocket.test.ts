import { WebSocketService } from '../websocket';

describe('WebSocket Service', () => {
  let ws: WebSocketService;
  const originalWebSocket = global.WebSocket;

  const createMockSocket = (readyState: number = WebSocket.CONNECTING) => ({
    onopen: null as (() => void) | null,
    onmessage: null as ((event: MessageEvent) => void) | null,
    onclose: null as (() => void) | null,
    onerror: null as ((event: Event) => void) | null,
    readyState,
    send: jest.fn(),
    close: jest.fn(),
  });

  const installWebSocketMock = (...sockets: ReturnType<typeof createMockSocket>[]) => {
    let index = 0;
    const mockConstructor = jest.fn().mockImplementation(() => {
      const socket = sockets[Math.min(index, sockets.length - 1)];
      index += 1;
      return socket as any;
    });
    Object.assign(mockConstructor, {
      CONNECTING: 0,
      OPEN: 1,
      CLOSING: 2,
      CLOSED: 3,
    });
    global.WebSocket = mockConstructor as unknown as typeof WebSocket;
    return mockConstructor;
  };

  beforeEach(() => {
    ws = new WebSocketService('ws://test-server');
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
    global.WebSocket = originalWebSocket;
  });

  test('connects to WebSocket server', async () => {
    const mockWs = createMockSocket(WebSocket.OPEN);
    const webSocketCtor = installWebSocketMock(mockWs);

    const connectPromise = ws.connect();

    mockWs.onopen!();

    await connectPromise;

    expect(webSocketCtor).toHaveBeenCalledWith('ws://test-server');
  });

  test('receives real-time updates', async () => {
    const mockWs = createMockSocket(WebSocket.OPEN);
    installWebSocketMock(mockWs);

    const handler = jest.fn();
    ws.subscribe('alert:created', handler);

    const connectPromise = ws.connect();
    mockWs.onopen!();
    await connectPromise;

    mockWs.onmessage!({
      data: JSON.stringify({
        type: 'alert:created',
        payload: { id: 'alert-1', message: 'Test' },
      }),
    } as MessageEvent);

    expect(handler).toHaveBeenCalledWith({ id: 'alert-1', message: 'Test' });
  });

  test('handles connection errors', async () => {
    const mockWs = createMockSocket(WebSocket.CLOSED);
    const webSocketCtor = installWebSocketMock(mockWs);

    const connectPromise = ws.connect();
    mockWs.onerror!(new Event('error'));
    await connectPromise;

    expect(ws.isConnected()).toBe(false);

    await ws.connect();

    expect(webSocketCtor).toHaveBeenCalledTimes(1);
  });

  test('reconnects on disconnect', async () => {
    jest.useFakeTimers();
    const firstSocket = createMockSocket(WebSocket.OPEN);
    const secondSocket = createMockSocket(WebSocket.OPEN);

    const webSocketCtor = installWebSocketMock(firstSocket, secondSocket);

    const connectPromise = ws.connect();
    firstSocket.onopen!();
    await connectPromise;

    firstSocket.onclose!();
    jest.advanceTimersByTime(1000);

    expect(webSocketCtor).toHaveBeenCalledTimes(2);
  });

  test('subscribes to events', () => {
    const handler = jest.fn();
    const unsubscribe = ws.subscribe('threat:detected', handler);

    expect(typeof unsubscribe).toBe('function');
  });

  test('unsubscribes from events', () => {
    const handler = jest.fn();
    const unsubscribe = ws.subscribe('threat:detected', handler);

    unsubscribe();

    // Handler should not be called after unsubscribe
    expect(ws['eventHandlers'].get('threat:detected')?.has(handler)).toBe(false);
  });

  test('sends messages', async () => {
    const mockWs = createMockSocket(WebSocket.OPEN);
    installWebSocketMock(mockWs);

    const connectPromise = ws.connect();
    mockWs.onopen!();
    await connectPromise;

    ws.send('alert:created', { id: 'alert-1' });

    expect(mockWs.send).toHaveBeenCalledWith(
      JSON.stringify({ type: 'alert:created', payload: { id: 'alert-1' } })
    );
  });

  test('checks connection status', async () => {
    const mockWs = createMockSocket(WebSocket.OPEN);
    installWebSocketMock(mockWs);

    expect(ws.isConnected()).toBe(false);

    const connectPromise = ws.connect();
    mockWs.onopen!();
    await connectPromise;

    expect(ws.isConnected()).toBe(true);
  });
});
