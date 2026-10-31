import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { type AddressInfo, isIP, Socket } from "node:net";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { SocksClient } from "socks";
import {
  Candidate,
  candidateFoundation,
  candidatePriority,
  classes,
  Message,
  methods,
  parseMessage,
  type TransactionRequestOptions,
  TurnProtocol,
} from "werift-ice";
import type { Address, Transport } from "werift-ice/lib/common/src/index.js";
import { splitTurnTcpFrames } from "werift-ice/lib/ice/src/turn/frame.js";

export interface TurnServer {
  readonly host: string;
  readonly port: number;
  readonly transport: "tcp";
  readonly username: string;
  readonly credential: string;
}

export interface IceObservation {
  readonly candidates: readonly {
    readonly value: string;
    readonly elapsed_ms: number;
  }[];
  readonly complete_at_ms: number;
}

export type TargetProxy = URL | null;

/** Validate before the paid WebSocket is opened; errors never echo proxy secrets. */
export function parseTargetProxy(value: string | null): TargetProxy {
  if (value === null || value === "") return null;
  try {
    if (typeof value !== "string") throw new TypeError();
    const url = new URL(value);
    if (
      !["http:", "https:", "socks5:"].includes(url.protocol) ||
      !url.hostname ||
      (url.pathname !== "" && url.pathname !== "/") ||
      url.search ||
      url.hash ||
      (url.port !== "" && (Number(url.port) < 1 || Number(url.port) > 65535))
    ) {
      throw new TypeError();
    }
    for (const value of [url.username, url.password]) {
      const decoded = decodeURIComponent(value);
      if (
        /[\r\n\0]/.test(decoded) ||
        (url.protocol.startsWith("socks") && Buffer.byteLength(decoded) > 255)
      ) {
        throw new TypeError();
      }
    }
    return url;
  } catch {
    throw new TypeError(
      "Target proxy must be an HTTP(S) or SOCKS5 proxy URL, or null/empty for direct",
    );
  }
}

async function connectTCP(
  host: string,
  port: number,
  signal: AbortSignal,
): Promise<Socket> {
  signal.throwIfAborted();
  const socket = new Socket();
  const aborted = () => socket.destroy();
  try {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    socket.once("error", reject);
    socket.once("connect", resolve);
    socket.once("close", () => reject(new Error("TCP connection closed")));
    signal.addEventListener("abort", aborted, { once: true });
    socket.connect({ host, port });
    await promise;
    signal.throwIfAborted();
    socket.pause();
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  } finally {
    signal.removeEventListener("abort", aborted);
  }
}

async function openStream(
  server: TurnServer,
  proxy: TargetProxy,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<Socket> {
  if (proxy === null) return connectTCP(server.host, server.port, signal);
  const host = proxy.hostname.replace(/^\[|\]$/g, "");
  const port = Number(
    proxy.port ||
      (proxy.protocol === "https:"
        ? 443
        : proxy.protocol === "http:"
          ? 80
          : 1080),
  );
  if (proxy.protocol.startsWith("socks")) {
    const socket = await connectTCP(host, port, signal);
    const aborted = () => socket.destroy();
    signal.addEventListener("abort", aborted, { once: true });
    try {
      signal.throwIfAborted();
      const pending = SocksClient.createConnection({
        command: "connect",
        proxy: {
          host,
          port,
          type: 5,
          userId: decodeURIComponent(proxy.username),
          password: decodeURIComponent(proxy.password),
        },
        destination: { host: server.host, port: server.port },
        existing_socket: socket,
        timeout: timeoutMs,
      });
      socket.resume();
      const result = await pending;
      signal.throwIfAborted();
      result.socket.pause();
      return result.socket;
    } catch (error) {
      socket.destroy();
      throw error;
    } finally {
      signal.removeEventListener("abort", aborted);
    }
  }
  signal.throwIfAborted();
  const { promise, resolve, reject } = Promise.withResolvers<Socket>();
  const destination = `${isIP(server.host) === 6 ? `[${server.host}]` : server.host}:${server.port}`;
  const headers: Record<string, string> = { Host: destination };
  if (proxy.username || proxy.password) {
    headers["Proxy-Authorization"] = `Basic ${Buffer.from(
      `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`,
    ).toString("base64")}`;
  }
  // Node's maintained HTTP client owns CONNECT parsing and TLS to HTTPS proxies.
  const request = (proxy.protocol === "https:" ? httpsRequest : httpRequest)({
    hostname: host,
    port,
    method: "CONNECT",
    path: destination,
    headers,
    agent: false,
  });
  const aborted = () => request.destroy(new Error("TURN connection cancelled"));
  signal.addEventListener("abort", aborted, { once: true });
  request.once("error", (error) => {
    signal.removeEventListener("abort", aborted);
    reject(error);
  });
  request.once("connect", (response, socket, head) => {
    signal.removeEventListener("abort", aborted);
    if (response.statusCode !== 200 || signal.aborted) {
      socket.destroy();
      reject(new Error("TURN proxy connection failed"));
      return;
    }
    socket.pause();
    if (head.length > 0) socket.unshift(head);
    resolve(socket);
  });
  request.end();
  if (signal.aborted) aborted();
  return promise;
}

/** werift exposes Transport but its TCP factory cannot accept a proxy stream. */
class SocketTransport implements Transport {
  readonly type = "tcp";
  readonly remoteAddress: Address;
  readonly #socket: Socket;
  #handler: ((data: Buffer, address: Address) => void) | undefined;

  constructor(
    socket: Socket,
    remoteAddress: Address,
    disconnected: () => void,
  ) {
    this.#socket = socket;
    this.remoteAddress = remoteAddress;
    socket.on("data", (data: Buffer) =>
      this.#handler?.(data, this.remoteAddress),
    );
    socket.on("error", disconnected);
    socket.once("close", disconnected);
  }

  get closed(): boolean {
    return this.#socket.destroyed;
  }

  get address(): AddressInfo {
    const address = this.#socket.address();
    if (typeof address === "string" || !("port" in address))
      throw new Error("TURN stream has no local address");
    return address;
  }

  get onData(): (data: Buffer, address: Address) => void {
    if (this.#handler === undefined)
      throw new Error("TURN stream reader has not been installed");
    return this.#handler;
  }

  set onData(handler: (data: Buffer, address: Address) => void) {
    this.#handler = handler;
    this.#socket.resume();
  }

  send(data: Buffer): Promise<void> {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    if (this.closed) {
      reject(new Error("TURN stream is closed"));
      return promise;
    }
    this.#socket.write(data, (error) => {
      if (error) reject(error);
      else resolve();
    });
    return promise;
  }

  async close(): Promise<void> {
    if (this.#socket.closed) return;
    const { promise, resolve } = Promise.withResolvers<void>();
    this.#socket.once("close", resolve);
    this.#socket.destroy();
    await promise;
  }
}

/** Only the public request hook is extended; provider auth and retries stay intact. */
class AbortableTurnProtocol extends TurnProtocol {
  requestSignal: AbortSignal;
  readonly #requests = new Set<Promise<[Message, Address]>>();

  constructor(server: TurnServer, transport: Transport, signal: AbortSignal) {
    super(
      [server.host, server.port],
      server.username,
      server.credential,
      600,
      transport,
    );
    this.requestSignal = signal;
  }

  override async request(
    request: Message,
    address: Address,
    integrityKey?: Buffer,
    retransmissionsOrOptions?: number | TransactionRequestOptions,
    onRequestSent?: (attempt: number) => void,
  ): Promise<[Message, Address]> {
    const options: TransactionRequestOptions | undefined =
      typeof retransmissionsOrOptions === "number"
        ? { retransmissions: retransmissionsOrOptions }
        : retransmissionsOrOptions;
    const signal =
      options?.signal === undefined
        ? this.requestSignal
        : AbortSignal.any([this.requestSignal, options.signal]);
    signal.throwIfAborted();
    const pending = super.request(
      request,
      address,
      integrityKey,
      { ...options, signal },
      onRequestSent,
    );
    this.#requests.add(pending);
    try {
      return await pending;
    } finally {
      this.#requests.delete(pending);
    }
  }

  async drain(): Promise<void> {
    await Promise.allSettled(this.#requests);
  }
}

function responseAddress(
  response: Message,
  attribute: "XOR-RELAYED-ADDRESS" | "XOR-MAPPED-ADDRESS",
): Address {
  const value: unknown = response.getAttributeValue(attribute);
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    typeof value[0] !== "string" ||
    !isIP(value[0]) ||
    typeof value[1] !== "number" ||
    !Number.isInteger(value[1]) ||
    value[1] < 1 ||
    value[1] > 65535
  ) {
    throw new Error(
      attribute === "XOR-RELAYED-ADDRESS"
        ? "TURN provider returned an invalid relay address"
        : "TURN provider returned an invalid mapped address",
    );
  }
  return [value[0], value[1]];
}

function responseLifetime(response: Message): number {
  const lifetime: unknown = response.getAttributeValue("LIFETIME");
  if (
    typeof lifetime !== "number" ||
    !Number.isInteger(lifetime) ||
    lifetime <= 0 ||
    lifetime > 0xffffffff
  ) {
    throw new Error("TURN provider returned an invalid allocation lifetime");
  }
  return lifetime;
}

async function release(
  turn: AbortableTurnProtocol,
  transport: Transport,
  disconnected: AbortSignal,
): Promise<void> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 2_000);
  turn.requestSignal = AbortSignal.any([disconnected, abort.signal]);
  try {
    if (!transport.closed && !disconnected.aborted) {
      const request = new Message(methods.REFRESH, classes.REQUEST);
      request.setAttribute("LIFETIME", 0);
      await turn.requestWithRetry(request, turn.server);
    }
  } catch {
    // A lost acknowledgement is not proof that the allocation was deleted.
  } finally {
    clearTimeout(timer);
    abort.abort();
    await turn.drain();
    await transport.close();
  }
}

/** One observed allocation, an abortable refresh schedule, and its TCP stream. */
export class RelayAllocation {
  readonly observation: IceObservation;
  readonly completion: Promise<"closed" | "failed">;
  readonly #turn: AbortableTurnProtocol;
  readonly #transport: Transport;
  readonly #disconnected: AbortSignal;
  readonly #stop = new AbortController();
  #closing: Promise<void> | undefined;

  constructor(
    turn: AbortableTurnProtocol,
    transport: Transport,
    observation: IceObservation,
    lifetime: number,
    signal: AbortSignal,
    disconnected: AbortSignal,
  ) {
    this.#turn = turn;
    this.#transport = transport;
    this.#disconnected = disconnected;
    this.observation = observation;
    const refreshing = AbortSignal.any([
      signal,
      disconnected,
      this.#stop.signal,
    ]);
    turn.requestSignal = refreshing;
    this.completion = this.#refresh(lifetime, refreshing, signal);
  }

  close(): Promise<void> {
    // Publish before cleanup runs; a stream close can re-enter this method.
    this.#closing ??= Promise.resolve().then(() => this.#release());
    return this.#closing;
  }

  async #refresh(
    lifetime: number,
    signal: AbortSignal,
    ownerSignal: AbortSignal,
  ): Promise<"closed" | "failed"> {
    try {
      while (true) {
        const deadline = performance.now() + (5 / 6) * lifetime * 1_000;
        let remaining = deadline - performance.now();
        while (remaining > 0) {
          await delay(Math.min(remaining, 0x7fffffff), undefined, {
            signal,
            ref: false,
          });
          remaining = deadline - performance.now();
        }
        signal.throwIfAborted();
        const request = new Message(methods.REFRESH, classes.REQUEST);
        request.setAttribute("LIFETIME", lifetime);
        const [response] = await this.#turn.requestWithRetry(
          request,
          this.#turn.server,
        );
        lifetime = responseLifetime(response);
        this.#turn.lifetime = lifetime;
      }
    } catch {
      return ownerSignal.aborted || this.#stop.signal.aborted
        ? "closed"
        : "failed";
    }
  }

  async #release(): Promise<void> {
    this.#stop.abort();
    await this.completion;
    await this.#turn.drain();
    await release(this.#turn, this.#transport, this.#disconnected);
  }
}

/** No PeerConnection, host gathering, local UDP socket, or direct fallback. */
export async function gatherRelay(
  server: TurnServer,
  proxy: TargetProxy,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<RelayAllocation> {
  const started = performance.now();
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), timeoutMs);
  const disconnected = new AbortController();
  const gathering = AbortSignal.any([
    signal,
    timeout.signal,
    disconnected.signal,
  ]);
  let turn: AbortableTurnProtocol | undefined;
  let transport: SocketTransport | undefined;
  let allocation: RelayAllocation | undefined;
  let socket: Socket | undefined;
  const streamDisconnected = () => disconnected.abort();
  try {
    gathering.throwIfAborted();
    if (proxy !== null && proxy.protocol === "socks5h:")
      throw new TypeError("TURN requires local DNS; use a SOCKS5 proxy URL");
    const host = server.host.replace(/^\[|\]$/g, "");
    let address = host;
    if (!isIP(host)) {
      const cancelled = Promise.withResolvers<never>();
      const aborted = () => cancelled.reject(gathering.reason);
      gathering.addEventListener("abort", aborted, { once: true });
      try {
        // OS lookup can finish in the background; the race consumes either outcome.
        address = (await Promise.race([lookup(host), cancelled.promise]))
          .address;
      } finally {
        gathering.removeEventListener("abort", aborted);
      }
    }
    gathering.throwIfAborted();
    const endpoint: TurnServer = { ...server, host: address };
    socket = await openStream(endpoint, proxy, gathering, timeoutMs);
    gathering.throwIfAborted();
    const remote: Address = [address, server.port];
    const stream = new SocketTransport(socket, remote, streamDisconnected);
    transport = stream;
    const provider = new AbortableTurnProtocol(endpoint, stream, gathering);
    turn = provider;
    let buffered: Buffer = Buffer.alloc(0);
    stream.onData = (data, source) => {
      const received =
        buffered.length === 0 ? data : Buffer.concat([buffered, data]);
      const { frames, rest, malformed } = splitTurnTcpFrames(received);
      buffered = rest;
      for (const frame of frames) {
        try {
          const message = parseMessage(frame);
          if (
            message === undefined ||
            (message.messageClass !== classes.RESPONSE &&
              message.messageClass !== classes.ERROR)
          )
            continue;
          const transaction = provider.transactions[message.transactionIdHex];
          if (transaction === undefined) continue;
          const verified =
            transaction.integrityKey === undefined
              ? message
              : parseMessage(frame, transaction.integrityKey);
          if (verified !== undefined)
            transaction.responseReceived(verified, source);
        } catch {
          // Ignore invalid messages without exposing wire data or credentials.
        }
      }
      // Both frame formats have a 16-bit body length; STUN has the larger header.
      if (malformed || rest.length >= 20 + 0xffff + 1) {
        streamDisconnected();
        void stream.close();
      }
    };
    // REQUESTED-TRANSPORT stores IP protocol 17 in the high byte.
    const request = new Message(methods.ALLOCATE, classes.REQUEST);
    request
      .setAttribute("LIFETIME", 600)
      .setAttribute("REQUESTED-TRANSPORT", 0x11000000);
    const [response] = await provider.requestWithRetry(
      request,
      provider.server,
    );
    provider.relayedAddress = responseAddress(response, "XOR-RELAYED-ADDRESS");
    provider.mappedAddress = responseAddress(response, "XOR-MAPPED-ADDRESS");
    const lifetime = responseLifetime(response);
    provider.lifetime = lifetime;
    const elapsed = performance.now() - started;
    const [relayHost, relayPort] = provider.relayedAddress;
    const candidate = new Candidate(
      candidateFoundation("relay", "udp", relayHost),
      1,
      "udp",
      candidatePriority("relay"),
      relayHost,
      relayPort,
      "relay",
    );
    allocation = new RelayAllocation(
      provider,
      stream,
      {
        candidates: [
          { value: `candidate:${candidate.toSdp()}`, elapsed_ms: elapsed },
        ],
        complete_at_ms: performance.now() - started,
      },
      lifetime,
      signal,
      disconnected.signal,
    );
    gathering.throwIfAborted();
    return allocation;
  } catch (error) {
    if (allocation !== undefined) await allocation.close();
    else if (turn !== undefined && transport !== undefined) {
      timeout.abort();
      await turn.drain();
      await release(turn, transport, disconnected.signal);
    } else {
      if (transport !== undefined) await transport.close();
      else socket?.destroy();
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
