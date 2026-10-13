/**
 * The secret a PIN slot is bound to. It lives on this device only, sealed
 * under a non-extractable AES-GCM key in IndexedDB: script on this origin can
 * ask the browser to use the key, but nothing can read it out, so a copy of
 * the vault ciphertext (a backup, a synced profile, a stolen localStorage
 * dump) cannot be brute-forced over the million possible PINs.
 *
 * Too many wrong PINs destroy the secret, which kills the PIN slot for good;
 * the passphrase still opens the vault and a new PIN can be set from there.
 */

const DB_NAME = 'stackwallet-device';
const STORE = 'secrets';
const RECORD = 'pin-binding';
export const PIN_FAILURES_KEY = 'stackwallet.pin.failures.v1';
export const MAX_PIN_FAILURES = 5;

interface Sealed {
  key: CryptoKey;
  iv: Uint8Array;
  ciphertext: ArrayBuffer;
}

function idb(): IDBFactory | null {
  try {
    return typeof indexedDB === 'undefined' ? null : indexedDB;
  } catch {
    return null;
  }
}

export function deviceSecretSupported(): boolean {
  return idb() !== null && typeof crypto !== 'undefined' && Boolean(crypto.subtle);
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const factory = idb();
    if (!factory) {
      reject(new Error('IndexedDB is unavailable'));
      return;
    }
    const req = factory.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
  });
}

function tx<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  op: (s: IDBObjectStore) => IDBRequest<T>,
) {
  return new Promise<T>((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = op(t.objectStore(STORE));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

async function read(): Promise<Sealed | undefined> {
  const db = await open();
  try {
    return (await tx(db, 'readonly', (s) => s.get(RECORD))) as Sealed | undefined;
  } finally {
    db.close();
  }
}

async function unseal(rec: Sealed): Promise<Uint8Array> {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: rec.iv as Uint8Array<ArrayBuffer> },
    rec.key,
    rec.ciphertext,
  );
  return new Uint8Array(plain);
}

/** The existing binding secret, or `null` when this device has none (or lost it). */
export async function loadDeviceSecret(): Promise<Uint8Array | null> {
  const rec = await read();
  return rec ? unseal(rec) : null;
}

/** A fresh binding secret; replaces any earlier one (and with it any earlier PIN). */
export async function createDeviceSecret(): Promise<Uint8Array> {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secret);
  const db = await open();
  try {
    await tx(db, 'readwrite', (s) => s.put({ key, iv, ciphertext } satisfies Sealed, RECORD));
  } finally {
    db.close();
  }
  return secret;
}

export async function destroyDeviceSecret(): Promise<void> {
  const db = await open();
  try {
    await tx(db, 'readwrite', (s) => s.delete(RECORD));
  } finally {
    db.close();
  }
}

export function pinFailures(storage: Pick<Storage, 'getItem'> | null): number {
  try {
    const n = Number(storage?.getItem(PIN_FAILURES_KEY) ?? '0');
    return Number.isInteger(n) && n > 0 ? n : 0;
  } catch {
    return 0;
  }
}

export function setPinFailures(storage: Pick<Storage, 'setItem' | 'removeItem'> | null, n: number) {
  try {
    if (n <= 0) storage?.removeItem(PIN_FAILURES_KEY);
    else storage?.setItem(PIN_FAILURES_KEY, String(n));
  } catch {
    // The binding secret is destroyed at the limit anyway; the counter is a courtesy.
  }
}
