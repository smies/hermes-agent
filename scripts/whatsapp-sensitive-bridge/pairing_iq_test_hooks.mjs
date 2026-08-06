export async function resolve(specifier, context, nextResolve) {
  const resolved = await nextResolve(specifier, context);
  if (resolved.url.endsWith('/node_modules/@whiskeysockets/baileys/lib/Socket/Client/websocket.js')) {
    return { url: 'hermes-rc14-test:websocket', shortCircuit: true };
  }
  return resolved;
}

export async function load(url, context, nextLoad) {
  if (url !== 'hermes-rc14-test:websocket') return nextLoad(url, context);
  return {
    format: 'module',
    shortCircuit: true,
    source: `
      import { EventEmitter } from 'node:events';
      export class WebSocketClient extends EventEmitter {
        constructor(url, config) {
          super();
          this.url = url;
          this.config = config;
          this.sent = [];
          this.closed = false;
          this.closing = false;
          globalThis.__hermesRc14MockSockets.push(this);
        }
        get isOpen() { return !this.closed && !this.closing; }
        get isClosed() { return this.closed; }
        get isClosing() { return this.closing; }
        get isConnecting() { return false; }
        connect() {}
        send(data, callback) {
          this.sent.push(data);
          callback?.();
          return true;
        }
        async close() {
          if (this.closed) return;
          this.closing = true;
          this.closed = true;
          this.closing = false;
          this.emit('close');
        }
      }
    `,
  };
}
