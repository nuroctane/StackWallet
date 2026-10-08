/**
 * One client API over two backends: the wasm build of the core (browser) and
 * Tauri IPC (desktop). Both return JSON that is Zod-validated here, so UI code
 * never sees an unchecked shape from either side.
 */
import { Decision, KeyGroup, Policy, PolicyContext, TxIntent, TxState } from './types.js';

export interface CoreClient {
  readonly backend: 'wasm' | 'tauri' | 'unavailable';
  coreVersion(): Promise<string>;
  evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext): Promise<Decision>;
  /** `null` when valid, otherwise the violation message. */
  validateKeyGroup(group: KeyGroup): Promise<string | null>;
  canTransition(from: TxState, to: TxState): Promise<boolean>;
  schemaSql(): Promise<string>;
}

interface WasmModule {
  default?: (input?: unknown) => Promise<unknown>;
  core_version(): string;
  evaluate_policy(policies: string, intent: string, ctx: string): string;
  validate_key_group(group: string): string | undefined;
  can_transition(from: string, to: string): boolean;
  schema_sql(): string;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export class WasmCoreClient implements CoreClient {
  readonly backend = 'wasm' as const;
  constructor(private readonly m: WasmModule) {}

  async coreVersion() {
    return this.m.core_version();
  }
  async evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext) {
    const out = this.m.evaluate_policy(
      JSON.stringify(policies),
      JSON.stringify(intent),
      JSON.stringify(ctx),
    );
    return Decision.parse(JSON.parse(out));
  }
  async validateKeyGroup(group: KeyGroup) {
    return this.m.validate_key_group(JSON.stringify(group)) ?? null;
  }
  async canTransition(from: TxState, to: TxState) {
    return this.m.can_transition(JSON.stringify(from), JSON.stringify(to));
  }
  async schemaSql() {
    return this.m.schema_sql();
  }
}

export class TauriCoreClient implements CoreClient {
  readonly backend = 'tauri' as const;
  constructor(private readonly invoke: Invoke) {}

  async coreVersion() {
    return this.invoke<string>('core_version');
  }
  async evaluatePolicy(policies: Policy[], intent: TxIntent, ctx: PolicyContext) {
    return Decision.parse(await this.invoke('evaluate_policy', { policies, intent, ctx }));
  }
  async validateKeyGroup(group: KeyGroup) {
    return (await this.invoke<string | null>('validate_key_group', { group })) ?? null;
  }
  async canTransition(from: TxState, to: TxState) {
    return this.invoke<boolean>('can_transition', { from, to });
  }
  async schemaSql() {
    return this.invoke<string>('schema_sql');
  }
}

/** Returned when neither backend can be loaded. Every call fails closed. */
export class UnavailableCoreClient implements CoreClient {
  readonly backend = 'unavailable' as const;
  constructor(readonly reason: string) {}

  private fail(): never {
    throw new Error(`core unavailable: ${this.reason}`);
  }
  async coreVersion(): Promise<string> {
    this.fail();
  }
  async evaluatePolicy(_p: Policy[], _i: TxIntent, _c: PolicyContext): Promise<Decision> {
    this.fail();
  }
  async validateKeyGroup(_g: KeyGroup): Promise<string | null> {
    this.fail();
  }
  async canTransition(_f: TxState, _t: TxState): Promise<boolean> {
    this.fail();
  }
  async schemaSql(): Promise<string> {
    this.fail();
  }
}

function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export interface CreateCoreClientOptions {
  /** URL of the wasm-pack output (`stackwallet_wasm.js`). Defaults to `/wasm/stackwallet_wasm.js`. */
  wasmUrl?: string;
}

export async function createCoreClient(opts: CreateCoreClientOptions = {}): Promise<CoreClient> {
  if (isTauri()) {
    const { invoke } = await import('@tauri-apps/api/core');
    return new TauriCoreClient(invoke as Invoke);
  }
  const url = opts.wasmUrl ?? '/wasm/stackwallet_wasm.js';
  try {
    // The wasm bundle is produced by `pnpm --filter @stackwallet/core-client build:wasm`
    // and served as a static asset; it is not part of the Vite module graph.
    const m = (await import(/* @vite-ignore */ url)) as WasmModule;
    if (typeof m.default === 'function') await m.default();
    return new WasmCoreClient(m);
  } catch (err) {
    return new UnavailableCoreClient(err instanceof Error ? err.message : String(err));
  }
}
