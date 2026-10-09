/**
 * Thrown by adapter methods that are deliberately not implemented yet. The
 * message names the capability and the phase it is scheduled for so a caller
 * never mistakes a stub for a silent success.
 */
export class NotImplementedError extends Error {
  override readonly name = 'NotImplementedError';

  constructor(
    readonly capability: string,
    readonly phase: string,
  ) {
    super(`${capability} is not implemented (${phase})`);
  }
}

/** The adapter was asked about a chain id that is not in its catalog. */
export class UnknownChainError extends Error {
  override readonly name = 'UnknownChainError';

  constructor(readonly chainId: string) {
    super(`unknown chain ${chainId}`);
  }
}

/** The public key's curve or encoding cannot produce an address on this chain. */
export class UnsupportedKeyError extends Error {
  override readonly name = 'UnsupportedKeyError';

  constructor(message: string) {
    super(message);
  }
}
