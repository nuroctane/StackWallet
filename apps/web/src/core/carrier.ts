/**
 * The byte pipe a `Session` runs over. The core authenticates every message,
 * so a carrier only has to deliver whole buffers in order; it never sees
 * plaintext. WebRTC data channels implement this in the browser; tests use an
 * in-memory pair.
 */
export interface Carrier {
  /** Resolves when the channel can carry bytes; rejects if it never opens. */
  readonly ready: Promise<void>;
  send(bytes: Uint8Array): void;
  onMessage(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: (reason: string) => void): void;
  close(reason?: string): void;
}

/** One side of a paste-based rendezvous: the offerer hands out text, the answerer replies. */
export interface OfferCarrier extends Carrier {
  acceptAnswer(text: string): Promise<void>;
}

export interface CarrierFactory {
  /** Create the offering side; `text` is what the other device must paste. */
  offer(): Promise<{ carrier: OfferCarrier; text: string }>;
  /** Create the answering side from the offerer's text; `text` goes back to the offerer. */
  answer(offerText: string): Promise<{ carrier: Carrier; text: string }>;
}

/** Two carriers wired back to back; `deliver` is synchronous so tests stay deterministic. */
export class LoopbackCarrier implements OfferCarrier {
  private peer: LoopbackCarrier | null = null;
  private message: ((bytes: Uint8Array) => void) | null = null;
  private closed: ((reason: string) => void) | null = null;
  private queue: Uint8Array[] = [];
  private open = false;
  private done = false;
  private resolveReady!: () => void;
  private rejectReady!: (err: Error) => void;
  readonly ready = new Promise<void>((resolve, reject) => {
    this.resolveReady = resolve;
    this.rejectReady = reject;
  });

  constructor() {
    this.ready.catch(() => undefined);
  }

  static pair(): [LoopbackCarrier, LoopbackCarrier] {
    const a = new LoopbackCarrier();
    const b = new LoopbackCarrier();
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  /** Marks both ends open, as a data channel would once ICE completes. */
  connect(): void {
    for (const end of [this, this.peer]) {
      if (end && !end.open && !end.done) {
        end.open = true;
        end.resolveReady();
      }
    }
  }

  send(bytes: Uint8Array): void {
    if (!this.open || !this.peer) throw new Error('carrier not open');
    this.peer.receive(bytes);
  }

  private receive(bytes: Uint8Array): void {
    if (this.message) this.message(bytes);
    else this.queue.push(bytes);
  }

  onMessage(cb: (bytes: Uint8Array) => void): void {
    this.message = cb;
    for (const bytes of this.queue.splice(0)) cb(bytes);
  }

  onClose(cb: (reason: string) => void): void {
    this.closed = cb;
  }

  close(reason = 'closed'): void {
    if (this.done) return;
    this.done = true;
    const wasOpen = this.open;
    this.open = false;
    if (!wasOpen) this.rejectReady(new Error(reason));
    this.closed?.(reason);
    const peer = this.peer;
    this.peer = null;
    if (wasOpen) peer?.close('peer closed');
  }

  async acceptAnswer(): Promise<void> {
    this.connect();
  }
}

/**
 * In-process rendezvous: `offer()` mints a pair and hands out its id as the
 * "text"; `answer(id)` returns the other end; `acceptAnswer` opens both.
 */
export class LoopbackFactory implements CarrierFactory {
  private readonly pending = new Map<string, LoopbackCarrier>();
  private seq = 0;

  async offer() {
    const [a, b] = LoopbackCarrier.pair();
    const text = `loop:${++this.seq}`;
    this.pending.set(text, b);
    return { carrier: a as OfferCarrier, text };
  }

  async answer(offerText: string) {
    const b = this.pending.get(offerText);
    if (!b) throw new Error('unknown offer');
    this.pending.delete(offerText);
    return { carrier: b as Carrier, text: `${offerText}:answer` };
  }
}
