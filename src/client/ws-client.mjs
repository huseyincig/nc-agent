import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX = 1024 * 1024;
/**
 * @param {string} k
 */
const expectedAccept = (k) =>
  crypto
    .createHash('sha1')
    .update(k + GUID)
    .digest('base64');

/**
 * @param {number} opcode
 * @param {Buffer | Uint8Array | string} [payload]
 */
export function maskedFrame(opcode, payload = Buffer.alloc(0)) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  if (p.length > MAX) throw new Error('WS_FRAME_TOO_LARGE');
  let h;
  if (p.length < 126) {
    h = Buffer.alloc(2);
    h[1] = 0x80 | p.length;
  } else if (p.length <= 0xffff) {
    h = Buffer.alloc(4);
    h[1] = 0x80 | 126;
    h.writeUInt16BE(p.length, 2);
  } else {
    h = Buffer.alloc(10);
    h[1] = 0x80 | 127;
    h.writeBigUInt64BE(BigInt(p.length), 2);
  }
  h[0] = 0x80 | opcode;
  const mask = crypto.randomBytes(4),
    out = Buffer.alloc(p.length);
  for (let i = 0; i < p.length; i++) out[i] = p[i] ^ mask[i % 4];
  return Buffer.concat([h, mask, out]);
}

export class ClientWebSocket extends EventEmitter {
  /**
   * @param {import('node:net').Socket} socket
   * @param {Buffer} [head]
   */
  constructor(socket, head = Buffer.alloc(0)) {
    super();
    this.socket = socket;
    this.buf = Buffer.from(head);
    this.closed = false;
    /** @type {Array<unknown>} */
    this.pendingJson = [];
    /** @type {Array<Buffer>} */
    this.pendingBinary = [];
    socket.setKeepAlive?.(true, 30000);
    socket.on('data', (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.#parse();
    });
    socket.on('close', () => {
      if (!this.closed) {
        this.closed = true;
        // Raw TCP close with no WebSocket close frame observed (hard kill,
        // crash, network cut): RFC 6455 code 1006 (abnormal closure). The
        // reconnect layer treats it like a server restart (prompt retry).
        this.emit('close', 1006, '');
      }
    });
    socket.on('error', (e) => this.emit('error', e));
    if (this.buf.length) setImmediate(() => this.#parse());
  }
  /**
   * @param {string | symbol} event
   * @param {(...args: Array<any>) => void} listener
   */
  on(event, listener) {
    super.on(event, listener);
    if (event === 'json' && this.pendingJson.length)
      queueMicrotask(() => {
        while (this.pendingJson.length && this.listenerCount('json'))
          this.emit('json', this.pendingJson.shift());
      });
    if (event === 'binary' && this.pendingBinary.length)
      queueMicrotask(() => {
        while (this.pendingBinary.length && this.listenerCount('binary'))
          this.emit('binary', this.pendingBinary.shift());
      });
    return this;
  }
  /**
   * @param {unknown} v
   */
  sendJson(v) {
    if (this.closed) throw new Error('WS_CLOSED');
    this.socket.write(maskedFrame(1, JSON.stringify(v)));
  }
  /**
   * @param {Buffer | Uint8Array | string} buffer
   */
  sendBinary(buffer) {
    if (this.closed) throw new Error('WS_CLOSED');
    this.socket.write(maskedFrame(2, buffer));
  }
  /**
   * @param {Buffer | Uint8Array | string} data
   */
  send(data) {
    if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      this.sendBinary(data);
    } else {
      if (this.closed) throw new Error('WS_CLOSED');
      this.socket.write(maskedFrame(1, String(data)));
    }
  }
  /**
   * @param {unknown} [v]
   */
  ping(v = '') {
    if (this.closed) return;
    this.socket.write(maskedFrame(9, String(v)));
  }
  /**
   * @param {number} [code]
   * @param {string} [reason]
   */
  close(code = 1000, reason = '') {
    if (this.closed) return;
    const r = Buffer.from(String(reason)),
      p = Buffer.alloc(2 + r.length);
    p.writeUInt16BE(code, 0);
    r.copy(p, 2);
    this.socket.write(maskedFrame(8, p));
    this.socket.end();
    this.closed = true;
  }
  /**
   * Immediate teardown for dead-peer detection (pong timeout). Unlike
   * close(), it never waits for a peer close frame that will never arrive
   * on a half-open socket. Emits 'close' exactly once.
   * @param {string} [reason]
   */
  destroy(reason = '') {
    if (this.closed) return;
    this.closed = true;
    try {
      this.socket.destroy();
    } catch {}
    // Locally-initiated teardown (pong watchdog): no peer code exists, so
    // the code slot stays null and the reason rides second. Listeners must
    // read (code, reason) — a null code keeps the escalating backoff.
    this.emit('close', null, reason || 'destroyed');
  }
  #parse() {
    while (this.buf.length >= 2) {
      const b0 = this.buf[0],
        b1 = this.buf[1],
        fin = Boolean(b0 & 0x80),
        opcode = b0 & 15,
        masked = Boolean(b1 & 0x80);
      let len = b1 & 127,
        off = 2;
      if (!fin || masked) {
        this.close(1002, 'bad server frame');
        return;
      }
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        const n = this.buf.readBigUInt64BE(2);
        if (n > BigInt(MAX)) {
          this.close(1009, 'too large');
          return;
        }
        len = Number(n);
        off = 10;
      }
      if (len > MAX) {
        this.close(1009, 'too large');
        return;
      }
      if (this.buf.length < off + len) return;
      const p = this.buf.subarray(off, off + len);
      this.buf = this.buf.subarray(off + len);
      if (opcode === 1) {
        try {
          const m = JSON.parse(p.toString('utf8'));
          if (this.listenerCount('json')) this.emit('json', m);
          else this.pendingJson.push(m);
        } catch {
          this.emit('protocolError', new Error('INVALID_JSON'));
        }
      } else if (opcode === 2) {
        const binPayload = Buffer.from(p);
        if (this.listenerCount('binary')) this.emit('binary', binPayload);
        else this.pendingBinary.push(binPayload);
      } else if (opcode === 8) {
        // Peer close frame: surface (code, reason) instead of dropping them
        // (the old bare emit hid 1012 restarts from the reconnect layer).
        let code = 1005;
        let reason = '';
        try {
          if (p.length >= 2) {
            code = p.readUInt16BE(0);
            if (!Number.isFinite(code) || code < 1000 || code > 4999) code = 1005;
            reason = p.length > 2 ? p.subarray(2).toString('utf8') : '';
          } else if (p.length === 0) {
            code = 1005;
          }
        } catch {
          code = 1005;
          reason = '';
        }
        try {
          this.socket.end();
        } catch {}
        this.closed = true;
        this.emit('close', code, reason);
        return;
      } else if (opcode === 9) this.socket.write(maskedFrame(10, p));
      else if (opcode === 10) this.emit('pong', p.toString());
    }
  }
}
/**
 * @param {string} serverUrl
 * @param {object} [options]
 * @param {string} [options.path]
 * @param {string} [options.token]
 * @param {string} [options.deviceProof]
 * @param {number} [options.timeoutMs]
 */
export function connectWebSocket(
  serverUrl,
  { path = '/agent/connect', token = '', deviceProof = '', timeoutMs = 8000 } = {}
) {
  const base = new URL(serverUrl),
    secure = base.protocol === 'https:',
    mod = secure ? https : http,
    key = crypto.randomBytes(16).toString('base64');
  /** @type {Record<string, string>} */
  const headers = {
    Connection: 'Upgrade',
    Upgrade: 'websocket',
    'Sec-WebSocket-Version': '13',
    'Sec-WebSocket-Key': key
  };
  if (token) {
    if (!deviceProof) throw new Error('DEVICE_PROOF_REQUIRED');
    headers.Authorization = 'NC-Device ' + token;
    headers['NC-Device-Proof'] = deviceProof;
  }
  return new Promise((resolve, reject) => {
    const req = mod.request({
      protocol: base.protocol,
      hostname: base.hostname,
      port: base.port || undefined,
      path,
      method: 'GET',
      headers
    });
    const timer = setTimeout(() => {
      req.destroy(new Error('WS_CONNECT_TIMEOUT'));
    }, timeoutMs);
    req.on('upgrade', (res, socket, head) => {
      clearTimeout(timer);
      const got = res.headers['sec-websocket-accept'];
      if (got !== expectedAccept(key)) {
        socket.destroy();
        reject(new Error('WS_BAD_ACCEPT'));
        return;
      }
      resolve(new ClientWebSocket(socket, head));
    });
    req.on('response', (res) => {
      clearTimeout(timer);
      res.resume();
      reject(new Error('WS_UPGRADE_HTTP_' + res.statusCode));
    });
    req.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    req.end();
  });
}
