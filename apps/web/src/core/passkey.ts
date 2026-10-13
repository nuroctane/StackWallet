/**
 * Passkeys as a local session factor: Face ID, Touch ID, Windows Hello,
 * Android biometrics or a security key, through WebAuthn's PRF extension.
 * The authenticator derives a 32-byte secret per credential only after its
 * own user verification; that secret opens this device's passkey slot in the
 * vault. Nothing is sent anywhere: the challenge is random and never checked
 * by a server, because there is none (D3). The PRF output is the factor.
 */

/** Fixed PRF input: the output is already unique per credential. */
const PRF_INPUT = new TextEncoder().encode('stackwallet/v1/vault-unlock-prf');

export function passkeySupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator !== 'undefined' &&
    Boolean(navigator.credentials)
  );
}

export function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

interface PrfResults {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };
}

function prfBytes(ext: PrfResults): Uint8Array | null {
  const first = ext.prf?.results?.first;
  if (!first) return null;
  const bytes =
    first instanceof ArrayBuffer
      ? new Uint8Array(first)
      : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
  return bytes.length === 32 ? new Uint8Array(bytes) : null;
}

function rpName(): string {
  return 'StackWallet';
}

/** Ask the authenticator for the slot secret of one credential. */
export async function passkeySecret(credentialId: string): Promise<Uint8Array> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        { type: 'public-key', id: fromBase64Url(credentialId) as Uint8Array<ArrayBuffer> },
      ],
      userVerification: 'required',
      timeout: 60_000,
      extensions: { prf: { eval: { first: PRF_INPUT } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No passkey was used');
  const out = prfBytes(cred.getClientExtensionResults() as PrfResults);
  if (!out) throw new Error('This authenticator does not support the PRF extension');
  return out;
}

/**
 * Register a new credential for this vault and read its PRF secret. Some
 * authenticators return the PRF result at registration; the rest need one
 * assertion right after (a second biometric prompt).
 */
export async function createPasskey(
  label: string,
): Promise<{ credentialId: string; secret: Uint8Array }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: rpName() },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'stackwallet-vault',
        displayName: `StackWallet · ${label}`,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      timeout: 60_000,
      extensions: { prf: { eval: { first: PRF_INPUT } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No passkey was created');
  const ext = cred.getClientExtensionResults() as PrfResults;
  if (ext.prf?.enabled === false)
    throw new Error('This authenticator does not support the PRF extension; use a PIN instead');
  const credentialId = toBase64Url(new Uint8Array(cred.rawId));
  const secret = prfBytes(ext) ?? (await passkeySecret(credentialId));
  return { credentialId, secret };
}
