import {
  ALGORAND_TESTNET,
  algorandApprovalValid,
  algorandTransferStatus,
  broadcastAlgorand,
  isValidAlgorandAddress,
  prepareAlgorand,
  type AlgorandAdapter,
  type AlgorandTx,
} from '@stackwallet/chains-algorand';
import {
  APTOS_TESTNET,
  aptosApprovalValid,
  aptosTransferStatus,
  broadcastAptos,
  normalizeAptosAddress,
  prepareAptos,
  type AptosAdapter,
  type AptosTx,
} from '@stackwallet/chains-aptos';
import {
  broadcastSui,
  isValidSuiAddress,
  normalizeSuiAddress,
  prepareSui,
  SUI_TESTNET,
  suiApprovalValid,
  suiTransferStatus,
  type SuiAdapter,
  type SuiTx,
} from '@stackwallet/chains-sui';
import {
  broadcastXrpl,
  isValidXrplAddress,
  prepareXrpl,
  XRPL_TESTNET,
  xrplApprovalValid,
  xrplTransferStatus,
  type XrplAdapter,
  type XrplTx,
} from '@stackwallet/chains-xrpl';
import {
  broadcastNear,
  isValidNearAddress,
  NEAR_TESTNET,
  nearApprovalValid,
  nearTransferStatus,
  prepareNear,
  type NearAdapter,
  type NearTx,
} from '@stackwallet/chains-near';
import {
  broadcastTon,
  isValidTonAddress,
  prepareTon,
  TON_TESTNET,
  tonApprovalValid,
  tonTransferStatus,
  type TonAdapter,
} from '@stackwallet/chains-ton';
import {
  broadcastCardano,
  CARDANO_PREPROD,
  cardanoApprovalValid,
  cardanoTransferStatus,
  isValidCardanoAddress,
  prepareCardano,
  type CardanoAdapter,
} from '@stackwallet/chains-cardano';
import {
  ANTELOPE_TESTNET,
  antelopeApprovalValid,
  antelopeTransferStatus,
  broadcastAntelope,
  isValidAntelopeAccount,
  memoError,
  prepareAntelope,
  type AntelopeAdapter,
} from '@stackwallet/chains-antelope';
import {
  broadcastMultiversx,
  isValidMultiversxAddress,
  MULTIVERSX_DEVNET,
  multiversxApprovalValid,
  multiversxTransferStatus,
  prepareMultiversx,
  type MultiversxAdapter,
} from '@stackwallet/chains-multiversx';
import {
  broadcastTezos,
  isValidTezosAddress,
  prepareTezos,
  TEZOS_SHADOWNET,
  tezosApprovalValid,
  tezosTransferStatus,
  type TezosAdapter,
} from '@stackwallet/chains-tezos';
import {
  broadcastStacks,
  isValidStacksAddress,
  prepareStacks,
  STACKS_TESTNET,
  stacksApprovalValid,
  stacksTransferStatus,
  type StacksAdapter,
} from '@stackwallet/chains-stacks';
import {
  broadcastVechain,
  isValidVechainAddress,
  normalizeVechainAddress,
  prepareVechain,
  VECHAIN_TESTNET,
  vechainApprovalValid,
  vechainTransferStatus,
  type VechainAdapter,
} from '@stackwallet/chains-vechain';
import {
  broadcastHyperliquid,
  HYPERLIQUID_TESTNET,
  hyperliquidApprovalValid,
  hyperliquidTransferStatus,
  isValidHyperliquidAddress,
  normalizeHyperliquidAddress,
  prepareHyperliquid,
  type HyperliquidAdapter,
} from '@stackwallet/chains-hyperliquid';
import {
  broadcastStarknet,
  isValidStarknetAddress,
  normalizeStarknetAddress,
  prepareStarknet,
  STARKNET_SEPOLIA,
  starknetApprovalValid,
  starknetTransferStatus,
  type StarknetAdapter,
} from '@stackwallet/chains-starknet';
import {
  broadcastIcon,
  ICON_LISBON,
  iconApprovalValid,
  iconTransferStatus,
  isValidIconAddress,
  prepareIcon,
  type IconAdapter,
} from '@stackwallet/chains-icon';
import {
  broadcastEverscale,
  everscaleApprovalValid,
  everscaleTransferStatus,
  isValidEverscaleAddress,
  prepareEverscale,
  VENOM_TESTNET,
  type EverscaleAdapter,
} from '@stackwallet/chains-everscale';
import {
  broadcastWaves,
  isValidWavesAddress,
  prepareWaves,
  WAVES_TESTNET,
  wavesApprovalValid,
  wavesTransferStatus,
  type WavesAdapter,
} from '@stackwallet/chains-waves';
import {
  broadcastRadix,
  isValidRadixAddress,
  prepareRadix,
  RADIX_STOKENET,
  radixApprovalValid,
  radixTransferStatus,
  type RadixAdapter,
} from '@stackwallet/chains-radix';
import {
  broadcastIcp,
  ICP_MAINNET,
  icpApprovalValid,
  icpTransferStatus,
  isValidIcpAddress,
  prepareIcp,
  type IcpAdapter,
} from '@stackwallet/chains-icp';
import {
  broadcastErgo,
  ERGO_TESTNET,
  ergoAddressBytes,
  ergoApprovalValid,
  ergoTransferStatus,
  prepareErgo,
  type ErgoAdapter,
} from '@stackwallet/chains-ergo';
import {
  ALEPHIUM_TESTNET,
  alphApprovalValid,
  alphTransferStatus,
  broadcastAlph,
  isValidAlphAddress,
  prepareAlph,
  type AlephiumAdapter,
} from '@stackwallet/chains-alephium';
import {
  AETERNITY_TESTNET,
  aeternityApprovalValid,
  aeternityTransferStatus,
  broadcastAeternity,
  isValidAeternityAddress,
  prepareAeternity,
  type AeternityAdapter,
} from '@stackwallet/chains-aeternity';
import {
  CHIA_TESTNET,
  broadcastChia,
  chiaApprovalValid,
  chiaNetworkPrefix,
  chiaTransferStatus,
  isValidChiaAddress,
  prepareChia,
  type ChiaAdapter,
} from '@stackwallet/chains-chia';
import {
  broadcastFuel,
  FUEL_SEPOLIA,
  fuelApprovalValid,
  fuelTransferStatus,
  isValidFuelAddress,
  prepareFuel,
  type FuelAdapter,
} from '@stackwallet/chains-fuel';
import {
  AELF_TESTNET,
  aelfApprovalValid,
  aelfTransferStatus,
  broadcastAelf,
  isValidAelfAddress,
  prepareAelf,
  type AelfAdapter,
} from '@stackwallet/chains-aelf';
import {
  broadcastStarcoin,
  isValidStarcoinAddress,
  prepareStarcoin,
  STARCOIN_BARNARD,
  starcoinApprovalValid,
  starcoinTransferStatus,
  type StarcoinAdapter,
} from '@stackwallet/chains-starcoin';
import {
  base64Encode,
  broadcastObyte,
  isValidObyteAddress,
  OBYTE_TESTNET,
  obyteApprovalValid,
  obyteTransferStatus,
  prepareObyte,
  type ObyteAdapter,
} from '@stackwallet/chains-obyte';
import {
  broadcastChromia,
  CHROMIA_TESTNET,
  CHROMIA_UNREGISTERED_NOTICE,
  chromiaApprovalValid,
  chromiaTransferStatus,
  isValidChromiaAddress,
  prepareChromia,
  prepareChromiaRegistration,
  type ChromiaAdapter,
} from '@stackwallet/chains-chromia';
import {
  broadcastKeeta,
  isValidKeetaAddress,
  KEETA_TEST,
  keetaApprovalValid,
  keetaTransferStatus,
  prepareKeeta,
  type KeetaAdapter,
} from '@stackwallet/chains-keeta';
import {
  broadcastNamada,
  isValidNamadaAddress,
  NAMADA_HOUSEFIRE,
  namadaTransferStatus,
  prepareNamada,
  type NamadaAdapter,
} from '@stackwallet/chains-namada';
import { directory } from './persist.js';
import {
  broadcastBtcFork,
  btcForkApprovalValid,
  btcForkTransferStatus,
  isValidForkAddress,
  prepareBtcFork,
  SIGNING_CHAINS as BTCFORK_SIGNING,
  type BtcForkAdapter,
} from '@stackwallet/chains-btcfork';
import {
  broadcastGala,
  GALA_TESTNET,
  galaApprovalValid,
  galaTransferStatus,
  isValidGalaAddress,
  prepareGala,
  type GalaAdapter,
} from '@stackwallet/chains-gala';
import {
  broadcastMixin,
  isValidMixinAddress,
  MIXIN_MAINNET,
  mixinApprovalValid,
  mixinTransferStatus,
  prepareMixin,
  type MixinAdapter,
} from '@stackwallet/chains-mixin';
import {
  broadcastQubic,
  isValidQubicIdentity,
  prepareQubic,
  QUBIC_MAINNET,
  qubicApprovalValid,
  qubicTransferStatus,
  type QubicAdapter,
} from '@stackwallet/chains-qubic';
import {
  broadcastStellar,
  isValidStellarAddress,
  prepareStellar,
  STELLAR_TESTNET,
  stellarApprovalValid,
  stellarTransferStatus,
  type StellarAdapter,
} from '@stackwallet/chains-stellar';
import {
  broadcastSubstrate,
  isValidSubstrateAddress,
  prepareSubstrate,
  SUBSTRATE_WESTEND,
  SUBSTRATE_WESTEND_ASSET_HUB,
  substrateApprovalValid,
  substrateTransferStatus,
  type SubstrateAdapter,
} from '@stackwallet/chains-substrate';
import type { StellarTx, SubstrateTx } from '@stackwallet/core-client';

import {
  AlgorandTx as CoreAlgorandTx,
  AntelopeTx,
  CardanoTx,
  MultiversxTx,
  TezosTx,
  StacksTx,
  VechainTx,
  HyperliquidTx,
  StarknetTx,
  IconTx,
  EverscaleTx,
  WavesTx,
  RadixTx,
  IcpTx,
  ErgoTx,
  AlephiumTx,
  AeternityTx,
  ChiaTx,
  FuelTx,
  AelfTx,
  StarcoinTx,
  ObyteTx,
  ChromiaTx,
  ChromiaRegisterTx,
  KeetaTx,
  NamadaTx,
  BtcForkTx,
  GalaTx,
  MixinTx,
  QubicTx,
  TonTx,
} from '@stackwallet/core-client';

import { isActivationIntent, registerFamilySend } from './families.js';

const U128_MAX = (1n << 128n) - 1n;
const I64_MAX = (1n << 63n) - 1n;
const U64_MAX = (1n << 64n) - 1n;

registerFamilySend({
  family: 'substrate',
  unit: 'planck',
  signingChains: [SUBSTRATE_WESTEND, SUBSTRATE_WESTEND_ASSET_HUB],
  prepare: (a, intent, account) =>
    prepareSubstrate(a as unknown as SubstrateAdapter, intent, account.address),
  approvalValid: (a, tx) =>
    substrateApprovalValid(a as unknown as SubstrateAdapter, tx as SubstrateTx),
  expiredReason:
    'The mortal era ended, the runtime changed or the nonce moved; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastSubstrate(a as unknown as SubstrateAdapter, tx as SubstrateTx, raw),
  status: (a, tx, hash) =>
    substrateTransferStatus(a as unknown as SubstrateAdapter, tx as SubstrateTx, hash),
  form: {
    validate: (to, chainId) => isValidSubstrateAddress(to, chainId),
    invalid: 'Not a valid address for this network (SS58, checksum included)',
    placeholder: '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
    maxUnits: U128_MAX,
    note: 'Westend testnet transfer (transfer_keep_alive). It expires if not included within about 25 minutes, and it never drops your balance below the existential deposit.',
  },
});

registerFamilySend({
  family: 'stellar',
  unit: 'stroops',
  signingChains: [STELLAR_TESTNET],
  prepare: (a, intent, account) =>
    prepareStellar(a as unknown as StellarAdapter, intent, account.address),
  approvalValid: (a, tx) => stellarApprovalValid(a as unknown as StellarAdapter, tx as StellarTx),
  expiredReason:
    'The time bound passed, or the sequence or recipient changed; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastStellar(a as unknown as StellarAdapter, tx as StellarTx, raw),
  status: (a, tx, hash) =>
    stellarTransferStatus(a as unknown as StellarAdapter, tx as StellarTx, hash),
  form: {
    validate: (to) => isValidStellarAddress(to),
    invalid: 'Not a valid Stellar account (G…, checksum included)',
    placeholder: 'GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX',
    maxUnits: I64_MAX,
    note: 'Native XLM on Stellar testnet. No memo is attached, so do not send to exchange deposit addresses that require one. A new recipient needs at least 1 XLM.',
  },
});

registerFamilySend({
  family: 'aptos',
  unit: 'octas',
  signingChains: [APTOS_TESTNET],
  prepare: (a, intent, account) =>
    prepareAptos(a as unknown as AptosAdapter, intent, account.address),
  approvalValid: (a, tx) => aptosApprovalValid(a as unknown as AptosAdapter, tx as AptosTx),
  expiredReason:
    'The 30-minute lifetime passed or the sequence number moved; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastAptos(a as unknown as AptosAdapter, tx as AptosTx, raw),
  status: (a, tx, hash) => aptosTransferStatus(a as unknown as AptosAdapter, tx as AptosTx, hash),
  form: {
    validate: (to) => normalizeAptosAddress(to) !== undefined,
    normalize: (to) => normalizeAptosAddress(to) ?? to,
    invalid: 'Not a valid Aptos account address (0x…)',
    placeholder: '0x978c213990c4833df71548df7ce49d54c759d6b6d932de22b24d56060b7af2aa',
    maxUnits: U64_MAX,
    note: 'Native APT on Aptos testnet. The fee shown is a maximum; unused gas is not charged. The transfer expires 30 minutes after it is prepared.',
  },
});

registerFamilySend({
  family: 'sui',
  unit: 'mist',
  signingChains: [SUI_TESTNET],
  prepare: (a, intent, account) => prepareSui(a as unknown as SuiAdapter, intent, account.address),
  approvalValid: (a, tx) => suiApprovalValid(a as unknown as SuiAdapter, tx as SuiTx),
  expiredReason:
    'A gas coin was spent elsewhere or the gas price rose; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastSui(a as unknown as SuiAdapter, tx as SuiTx, raw),
  status: (a, tx, hash) => suiTransferStatus(a as unknown as SuiAdapter, tx as SuiTx, hash),
  hashCaseSensitive: true,
  form: {
    validate: (to) => isValidSuiAddress(to),
    normalize: (to) => normalizeSuiAddress(to),
    invalid: 'Not a full Sui address (0x + 64 hex)',
    placeholder: '0xa2d14fad60c56049ecf75246a481934691214ce413e6a8ae2fe6834c173a6133',
    maxUnits: U64_MAX,
    note: 'Native SUI on Sui testnet. Gas is paid from your coin objects and capped at the budget shown.',
  },
});

registerFamilySend({
  family: 'xrpl',
  unit: 'drops',
  signingChains: [XRPL_TESTNET],
  prepare: (a, intent, account, options) =>
    prepareXrpl(
      a as unknown as XrplAdapter,
      intent,
      account.address,
      account.publicKeyHex,
      options.tag === undefined ? {} : { destinationTag: Number(options.tag) },
    ),
  approvalValid: (a, tx) => xrplApprovalValid(a as unknown as XrplAdapter, tx as XrplTx),
  expiredReason:
    'The last ledger passed or the account sequence moved; propose and approve a fresh payment',
  broadcast: (a, tx, raw) => broadcastXrpl(a as unknown as XrplAdapter, tx as XrplTx, raw),
  status: (a, tx, hash) => xrplTransferStatus(a as unknown as XrplAdapter, tx as XrplTx, hash),
  form: {
    validate: (to) => isValidXrplAddress(to),
    invalid: 'Not a classic XRP Ledger address (r…, checksum included)',
    placeholder: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
    maxUnits: 100_000_000_000_000_000n,
    tag: {
      label: 'Destination tag (optional)',
      placeholder: 'e.g. 12345',
      validate: (tag) => /^(0|[1-9][0-9]{0,9})$/.test(tag) && Number(tag) <= 0xffff_ffff,
      invalid: 'A whole number from 0 to 4294967295',
      inputMode: 'numeric',
    },
    note: 'Native XRP on XRP Ledger testnet. Exchanges usually need a destination tag; check it before you send. A new account needs at least 1 XRP.',
  },
});
registerFamilySend({
  family: 'near',
  unit: 'yocto',
  signingChains: [NEAR_TESTNET],
  prepare: (a, intent, account) =>
    prepareNear(a as unknown as NearAdapter, intent, account.address),
  approvalValid: (a, tx) => nearApprovalValid(a as unknown as NearAdapter, tx as NearTx),
  expiredReason:
    'The reference block is about a day old or the key nonce moved; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastNear(a as unknown as NearAdapter, tx as NearTx, raw),
  status: (a, tx, hash) => nearTransferStatus(a as unknown as NearAdapter, tx as NearTx, hash),
  hashCaseSensitive: true,
  form: {
    validate: (to) => isValidNearAddress(to),
    invalid: 'Not a NEAR account id (lowercase name like alice.testnet, or 64-hex implicit id)',
    placeholder: 'alice.testnet',
    maxUnits: 10n ** 34n,
    note: 'Native NEAR on NEAR testnet, sent from the implicit account of this key (fund the 64-hex address first). No memo is attached.',
  },
});
registerFamilySend({
  family: 'algorand',
  unit: 'microalgos',
  signingChains: [ALGORAND_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareAlgorand(a as unknown as AlgorandAdapter, intent, account.address);
    return { ...r, unsigned: CoreAlgorandTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    algorandApprovalValid(a as unknown as AlgorandAdapter, tx as AlgorandTx),
  expiredReason: 'The last valid round passed; propose and approve a fresh payment',
  broadcast: (a, tx, raw) =>
    broadcastAlgorand(a as unknown as AlgorandAdapter, tx as AlgorandTx, raw),
  status: (a, tx, hash) =>
    algorandTransferStatus(a as unknown as AlgorandAdapter, tx as AlgorandTx, hash),
  hashCaseSensitive: true,
  form: {
    validate: (to) => isValidAlgorandAddress(to),
    invalid: 'Not a valid Algorand address (58 uppercase characters, checksum included)',
    placeholder: '7ULSIOC2UDDVWZH3PDGWAL5B3GI7327XNMJ4LDWXALVMQNPJ6YMB7QOADI',
    maxUnits: 10_000_000_000_000_000n,
    note: 'Native ALGO on Algorand testnet. No note is attached, so do not send to exchange deposit addresses that require one. Accounts keep at least 0.1 ALGO.',
  },
});

registerFamilySend({
  family: 'ton',
  unit: 'nanoton',
  signingChains: [TON_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareTon(a as unknown as TonAdapter, intent, account.address);
    return { ...r, unsigned: TonTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => tonApprovalValid(a as unknown as TonAdapter, TonTx.parse(tx)),
  expiredReason:
    'The 30-minute lifetime passed or the wallet seqno moved; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastTon(a as unknown as TonAdapter, TonTx.parse(tx), raw),
  status: (a, tx, hash) => tonTransferStatus(a as unknown as TonAdapter, TonTx.parse(tx), hash),
  form: {
    validate: (to) => isValidTonAddress(to.trim()),
    invalid: 'Not a valid TON address (EQ/UQ/kQ/0Q…, or 0:<hex>)',
    placeholder: '0QAfOEHwTpozSfZP4WJsbwRbVNbC2DnT4AAVGDMdbCAzUpnx',
    maxUnits: U64_MAX,
    note: 'Native TON on testnet. The first transfer deploys your wallet contract. The fee shown is a maximum. No comment is attached, so exchanges that need one cannot be paid.',
  },
});

registerFamilySend({
  family: 'cardano',
  unit: 'lovelace',
  signingChains: [CARDANO_PREPROD],
  prepare: async (a, intent, account) => {
    const r = await prepareCardano(a as unknown as CardanoAdapter, intent, account.address);
    return { ...r, unsigned: CardanoTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    cardanoApprovalValid(a as unknown as CardanoAdapter, CardanoTx.parse(tx)),
  expiredReason:
    'The two-hour lifetime passed or an input was spent elsewhere; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastCardano(a as unknown as CardanoAdapter, CardanoTx.parse(tx), raw),
  status: (a, tx, hash) =>
    cardanoTransferStatus(a as unknown as CardanoAdapter, CardanoTx.parse(tx), hash),
  form: {
    validate: (to, chainId) => isValidCardanoAddress(to.trim(), chainId),
    normalize: (to) => to.trim(),
    invalid: 'Not a Cardano preprod address (addr_test1…, key payment, checksum included)',
    placeholder:
      'addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae',
    maxUnits: 45_000_000_000_000_000n,
    note: 'Native ADA on Cardano preprod, at least about 0.97 ADA per transfer. UTxOs that hold tokens are never spent; send them from a full Cardano wallet.',
  },
});

registerFamilySend({
  family: 'antelope',
  unit: 'antelopeUnits',
  signingChains: [ANTELOPE_TESTNET],
  prepare: async (a, intent, account, options) => {
    const adapter = a as unknown as AntelopeAdapter;
    // The identity is the key; the sending account is whichever on-chain name it controls.
    const linked = await adapter.accountsForKey(account.address, intent.chainId);
    const pick = linked.find((l) => l.permission === 'active') ?? linked[0];
    if (!pick) {
      throw new Error(
        'No account on this network lists this key yet. Someone has to create an account for it first.',
      );
    }
    const r = await prepareAntelope(
      adapter,
      intent,
      pick.account,
      account.address,
      options.tag === undefined ? {} : { memo: options.tag },
    );
    return { ...r, unsigned: AntelopeTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    antelopeApprovalValid(a as unknown as AntelopeAdapter, AntelopeTx.parse(tx)),
  expiredReason:
    'The 30-minute lifetime passed or the key no longer satisfies the account permission; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastAntelope(a as unknown as AntelopeAdapter, AntelopeTx.parse(tx), raw),
  status: (a, tx, hash) =>
    antelopeTransferStatus(a as unknown as AntelopeAdapter, AntelopeTx.parse(tx), hash),
  form: {
    validate: (to) => isValidAntelopeAccount(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not an account name (1-12 characters: a-z, 1-5 and dots)',
    placeholder: 'swt1d1faf1fv',
    maxUnits: (1n << 62n) - 1n,
    tag: {
      label: 'Memo (optional)',
      placeholder: 'exchange deposit memo',
      validate: (memo) => memoError(memo) === undefined,
      invalid: 'At most 256 bytes, no control characters',
    },
    note: 'Native WAX on WAX testnet. The recipient must be an existing account name; exchanges usually need a memo. Transfers use staked CPU and NET instead of a token fee.',
  },
});

registerFamilySend({
  family: 'multiversx',
  unit: 'attoegld',
  signingChains: [MULTIVERSX_DEVNET],
  prepare: async (a, intent, account) => {
    const r = await prepareMultiversx(a as unknown as MultiversxAdapter, intent, account.address);
    return { ...r, unsigned: MultiversxTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    multiversxApprovalValid(a as unknown as MultiversxAdapter, MultiversxTx.parse(tx)),
  expiredReason:
    'Another transaction used this nonce, so the transfer can never land; propose and approve a fresh one',
  broadcast: (a, tx, raw) =>
    broadcastMultiversx(a as unknown as MultiversxAdapter, MultiversxTx.parse(tx), raw),
  status: (a, tx, hash) =>
    multiversxTransferStatus(a as unknown as MultiversxAdapter, MultiversxTx.parse(tx), hash),
  form: {
    validate: (to) => isValidMultiversxAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a MultiversX address (erd1…, checksum included)',
    placeholder: 'erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th',
    maxUnits: 31_415_926n * 10n ** 18n,
    note: 'Devnet EGLD only. The fee is 50,000 gas at the network minimum price (0.00005 EGLD).',
  },
});

registerFamilySend({
  family: 'tezos',
  unit: 'mutez',
  signingChains: [TEZOS_SHADOWNET],
  prepare: async (a, intent, account) => {
    // The public key lets the first send reveal the account's manager key.
    const r = await prepareTezos(
      a as unknown as TezosAdapter,
      intent,
      account.address,
      account.publicKeyHex,
    );
    return { ...r, unsigned: TezosTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => tezosApprovalValid(a as unknown as TezosAdapter, TezosTx.parse(tx)),
  expiredReason:
    'The branch aged out (about 600 blocks) or the counter moved; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) => broadcastTezos(a as unknown as TezosAdapter, TezosTx.parse(tx), raw),
  status: (a, tx, hash) =>
    tezosTransferStatus(a as unknown as TezosAdapter, TezosTx.parse(tx), hash),
  hashCaseSensitive: true,
  form: {
    validate: (to) => isValidTezosAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a Tezos account (tz1/tz2/tz3/tz4, checksum included; KT1 contracts are refused)',
    placeholder: 'tz1VQA4RP4fLjEEMW2FR4pE9kAg5abb5h5GL',
    maxUnits: (1n << 63n) - 1n,
    note: 'Native tez on Tezos Shadownet, to tz1/tz2/tz3/tz4 accounts only. The first send reveals your key, and a never-used recipient burns 0.064 tez.',
  },
});

registerFamilySend({
  family: 'stacks',
  unit: 'microstx',
  signingChains: [STACKS_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareStacks(a as unknown as StacksAdapter, intent, account.address);
    return { ...r, unsigned: StacksTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => stacksApprovalValid(a as unknown as StacksAdapter, StacksTx.parse(tx)),
  expiredReason:
    'Another transaction used this nonce, so the transfer can never land; propose and approve a fresh one',
  broadcast: (a, tx, raw) =>
    broadcastStacks(a as unknown as StacksAdapter, StacksTx.parse(tx), raw),
  status: (a, tx, hash) =>
    stacksTransferStatus(a as unknown as StacksAdapter, StacksTx.parse(tx), hash),
  form: {
    validate: (to, chainId) => isValidStacksAddress(to.trim(), chainId),
    normalize: (to) => to.trim(),
    invalid: 'Not a Stacks testnet address (ST… or SN…, checksum included; contracts are refused)',
    placeholder: 'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG',
    maxUnits: (1n << 64n) - 1n,
    note: 'Native STX on Stacks testnet with an empty memo, so not for exchange deposits that need one. The fee is the network estimate, at most 1 STX.',
  },
});

registerFamilySend({
  family: 'vechain',
  unit: 'vetWei',
  signingChains: [VECHAIN_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareVechain(a as unknown as VechainAdapter, intent, account.address);
    return { ...r, unsigned: VechainTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    vechainApprovalValid(a as unknown as VechainAdapter, VechainTx.parse(tx)),
  expiredReason: 'The 30-minute block window passed; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastVechain(a as unknown as VechainAdapter, VechainTx.parse(tx), raw),
  status: (a, tx, hash) =>
    vechainTransferStatus(a as unknown as VechainAdapter, VechainTx.parse(tx), hash),
  form: {
    validate: (to) => isValidVechainAddress(to.trim()),
    normalize: (to) => normalizeVechainAddress(to.trim()) ?? to.trim(),
    invalid: 'Not a VeChain address (0x + 40 hex; the zero address is refused)',
    placeholder: '0x7495dee08f1340fa1fbda59c979f799d7d676fce',
    maxUnits: (1n << 128n) - 1n,
    note: 'Fees are paid in VTHO, not VET. The sender needs about 0.21 VTHO per transfer.',
  },
});

registerFamilySend({
  family: 'hyperliquid',
  unit: 'hlUsdMicro',
  signingChains: [HYPERLIQUID_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareHyperliquid(a as unknown as HyperliquidAdapter, intent, account.address);
    return { ...r, unsigned: HyperliquidTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    hyperliquidApprovalValid(a as unknown as HyperliquidAdapter, HyperliquidTx.parse(tx)),
  expiredReason:
    'The one-day nonce window passed without the transfer landing; propose and approve a fresh one',
  broadcast: (a, tx, raw) =>
    broadcastHyperliquid(a as unknown as HyperliquidAdapter, HyperliquidTx.parse(tx), raw),
  status: (a, tx, hash) =>
    hyperliquidTransferStatus(a as unknown as HyperliquidAdapter, HyperliquidTx.parse(tx), hash),
  form: {
    validate: (to) => isValidHyperliquidAddress(to.trim()),
    normalize: (to) => normalizeHyperliquidAddress(to.trim()) ?? to.trim(),
    invalid: 'Not an Ethereum-style address (0x + 40 hex; the zero address is refused)',
    placeholder: '0x5e9ee1089755c3435139848e47e6635505d5a13a',
    maxUnits: 1_000_000_000_000_000n,
    note: 'USDC from the HyperCore perp account on testnet. The balance must be withdrawable, not in margin. A first-time recipient costs the sender 1 USDC.',
  },
});

registerFamilySend({
  family: 'starknet',
  unit: 'fri',
  signingChains: [STARKNET_SEPOLIA],
  prepare: async (a, intent, account) => {
    const r = await prepareStarknet(a as unknown as StarknetAdapter, intent, account.address);
    return { ...r, unsigned: StarknetTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    starknetApprovalValid(a as unknown as StarknetAdapter, StarknetTx.parse(tx)),
  // v3 transactions have no expiry; the status helper never reports one either.
  expiredReason: 'Starknet transactions do not expire; propose and approve a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastStarknet(a as unknown as StarknetAdapter, StarknetTx.parse(tx), raw),
  status: (a, tx, hash) =>
    starknetTransferStatus(a as unknown as StarknetAdapter, StarknetTx.parse(tx), hash),
  form: {
    validate: (to) => isValidStarknetAddress(to.trim()),
    normalize: (to) => normalizeStarknetAddress(to.trim()) ?? to.trim(),
    invalid: 'Not a Starknet address (0x + 64 hex)',
    placeholder: '0x060827ce138bbccc66ce987d602f8413eabe379a860e89f1f4192a5e936da657',
    maxUnits: (1n << 128n) - 1n,
    note: 'Native STRK on Starknet Sepolia. The first send deploys your account contract: the address must already hold enough STRK to pay both fees.',
  },
});

registerFamilySend({
  family: 'icon',
  unit: 'loop',
  signingChains: [ICON_LISBON],
  prepare: async (a, intent, account) => {
    const r = await prepareIcon(a as unknown as IconAdapter, intent, account.address);
    return { ...r, unsigned: IconTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => iconApprovalValid(a as unknown as IconAdapter, IconTx.parse(tx)),
  expiredReason: 'The timestamp fell outside the node acceptance window; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastIcon(a as unknown as IconAdapter, IconTx.parse(tx), raw),
  status: (a, tx, hash) => iconTransferStatus(a as unknown as IconAdapter, IconTx.parse(tx), hash),
  form: {
    validate: (to) => isValidIconAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not an ICON address (hx + 40 hex)',
    placeholder: 'hx9d8a8376e7db9f00478feb9a46f44f0d051aab57',
    maxUnits: 1_000_000_000_000_000_000_000_000_000n,
    note: 'Native ICX on the Lisbon testnet. A transfer costs a fixed 100,000 step fee and must be signed and sent within about an hour of creation.',
  },
});

registerFamilySend({
  family: 'everscale',
  unit: 'evers',
  signingChains: [VENOM_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareEverscale(a as unknown as EverscaleAdapter, intent, account.address);
    return { ...r, unsigned: EverscaleTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    everscaleApprovalValid(a as unknown as EverscaleAdapter, EverscaleTx.parse(tx)),
  expiredReason: 'The message lifetime elapsed; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastEverscale(a as unknown as EverscaleAdapter, EverscaleTx.parse(tx), raw),
  status: (a, tx, hash) =>
    everscaleTransferStatus(a as unknown as EverscaleAdapter, EverscaleTx.parse(tx), hash),
  form: {
    validate: (to) => isValidEverscaleAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a Venom/Everscale address (0: + 64 hex)',
    placeholder: '0:120094dedd73dfa077fe4bdaeb97e66455ca8ace3ed68b194979a1b78bc98ee5',
    maxUnits: 18_446_744_073_709_551_615n,
    note: 'Native VENOM on testnet. The first transfer deploys your wallet contract and the fee shown is a maximum; the message expires after 30 minutes.',
  },
});

registerFamilySend({
  family: 'waves',
  unit: 'wavelets',
  signingChains: [WAVES_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareWaves(
      a as unknown as WavesAdapter,
      intent,
      account.address,
      account.publicKeyHex,
    );
    return { ...r, unsigned: WavesTx.parse(r.unsigned) };
  },
  // Approval is purely clock-based on Waves: the node drops a stale timestamp.
  approvalValid: async (_a, tx) => wavesApprovalValid(WavesTx.parse(tx)),
  expiredReason: 'The node dropped the stale transaction; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastWaves(a as unknown as WavesAdapter, WavesTx.parse(tx), raw),
  status: (a, tx, hash) =>
    wavesTransferStatus(a as unknown as WavesAdapter, WavesTx.parse(tx), hash),
  form: {
    validate: (to) => isValidWavesAddress(to.trim(), WAVES_TESTNET),
    normalize: (to) => to.trim(),
    invalid: 'Not a Waves testnet address (base58, 26 bytes)',
    placeholder: '3NAsmeu5DhFgdgJvuWxFpPnwcEG8W76BJG2Cd',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'Native WAVES on testnet with a fixed 0.001 WAVES fee. A transaction goes stale about two hours after it is built.',
  },
});

registerFamilySend({
  family: 'radix',
  unit: 'attos',
  signingChains: [RADIX_STOKENET],
  prepare: async (a, intent, account) => {
    const r = await prepareRadix(a as unknown as RadixAdapter, intent, account.address);
    return { ...r, unsigned: RadixTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => radixApprovalValid(a as unknown as RadixAdapter, RadixTx.parse(tx)),
  expiredReason: 'The epoch window closed; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastRadix(a as unknown as RadixAdapter, RadixTx.parse(tx), raw),
  status: (a, tx, hash) =>
    radixTransferStatus(a as unknown as RadixAdapter, RadixTx.parse(tx), hash),
  form: {
    validate: (to) => isValidRadixAddress(to.trim(), RADIX_STOKENET),
    normalize: (to) => to.trim(),
    invalid: 'Not a Radix Stokenet account (account_tdx_2_...)',
    placeholder: 'account_tdx_2_12ynqzf78g3mtyufkch3ccqpmv6ugnawgqqe0hq0tc06y73dr0sf2qk',
    maxUnits: 30_000_000_000_000_000_000_000_000_000n,
    note: 'Native XRD on Radix Stokenet. 5 XRD is locked as a fee deposit and the unused part is refunded by the ledger; the transfer expires about 45 minutes after it is built.',
  },
});

registerFamilySend({
  family: 'icp',
  unit: 'e8s',
  signingChains: [ICP_MAINNET],
  prepare: async (a, intent, account) => {
    const r = await prepareIcp(a as unknown as IcpAdapter, intent, account.address);
    return { ...r, unsigned: IcpTx.parse(r.unsigned) };
  },
  approvalValid: async (a, tx) => icpApprovalValid(a as unknown as IcpAdapter, IcpTx.parse(tx)),
  expiredReason: 'The ingress expiry passed; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastIcp(a as unknown as IcpAdapter, IcpTx.parse(tx), raw),
  status: (a, tx, hash) => icpTransferStatus(a as unknown as IcpAdapter, IcpTx.parse(tx), hash),
  form: {
    validate: (to) => isValidIcpAddress(to.trim()),
    normalize: (to) => to.trim().toLowerCase(),
    invalid: 'Not an ICP account identifier (64 hex with checksum)',
    placeholder: 'b7350197f5cc3597b65d5647d94b48b6d5e6a3ec7760e3bc91baba0b4597bdb5',
    maxUnits: 500_000_000_000_000_000n,
    note: 'Native ICP on mainnet (there is no public testnet). The fee is a fixed 0.0001 ICP and the transfer expires about four minutes after preparation.',
  },
});

registerFamilySend({
  family: 'ergo',
  unit: 'nanoerg',
  signingChains: [ERGO_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareErgo(a as unknown as ErgoAdapter, intent, account.address);
    return { ...r, unsigned: ErgoTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => ergoApprovalValid(a as unknown as ErgoAdapter, ErgoTx.parse(tx)),
  expiredReason: 'An input was spent; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastErgo(a as unknown as ErgoAdapter, ErgoTx.parse(tx), raw),
  status: (a, tx, hash) => ergoTransferStatus(a as unknown as ErgoAdapter, ErgoTx.parse(tx), hash),
  form: {
    validate: (to) => ergoAddressBytes(to.trim())?.[0] === 0x11,
    normalize: (to) => to.trim(),
    invalid: 'Not an Ergo testnet P2PK address (base58, starts with 3)',
    placeholder: '3WwmRJYcKmDVN3Uqdbh52cn8BmmWfBUVQPxtrJidXb3ofAZmnNEG',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'Ergo testnet transfer. The fee is 0.001 ERG and change returns to you; only plain P2PK boxes are spent.',
  },
});

registerFamilySend({
  family: 'alephium',
  unit: 'attoalph',
  signingChains: [ALEPHIUM_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareAlph(
      a as unknown as AlephiumAdapter,
      intent,
      account.address,
      account.publicKeyHex,
    );
    return { ...r, unsigned: AlephiumTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    alphApprovalValid(a as unknown as AlephiumAdapter, AlephiumTx.parse(tx)),
  expiredReason: 'An input was spent; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastAlph(a as unknown as AlephiumAdapter, AlephiumTx.parse(tx), raw),
  status: (a, tx, hash) =>
    alphTransferStatus(a as unknown as AlephiumAdapter, AlephiumTx.parse(tx), hash),
  form: {
    validate: (to) => isValidAlphAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not an Alephium address (base58, starts with 1)',
    placeholder: '13nr2XuF1VYfEgBLsXBQFrZcfzNvACP8cDz5CdAwk6BUz',
    maxUnits: 340_282_366_920_938_463_463_374_607_431_768_211_455n,
    note: 'Alephium is UTXO-based: the wallet selects UTXOs and returns change to you. Timelocked and token-carrying UTXOs are never spent; addresses have no checksum, so a typo is final.',
  },
});

registerFamilySend({
  family: 'aeternity',
  unit: 'aettos',
  signingChains: [AETERNITY_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareAeternity(a as unknown as AeternityAdapter, intent, account.address);
    return { ...r, unsigned: AeternityTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    aeternityApprovalValid(a as unknown as AeternityAdapter, AeternityTx.parse(tx)),
  expiredReason: 'The transaction outlived its ttl; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastAeternity(a as unknown as AeternityAdapter, AeternityTx.parse(tx), raw),
  status: (a, tx, hash) =>
    aeternityTransferStatus(a as unknown as AeternityAdapter, AeternityTx.parse(tx), hash),
  form: {
    validate: (to) => isValidAeternityAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not an Aeternity account address (ak_…)',
    placeholder: 'ak_2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK',
    maxUnits: 1_000_000_000_000_000_000_000_000_000_000n,
    note: 'AE transfers carry no memo and cannot be replaced or cancelled once broadcast. A transfer to a fresh address creates the account.',
  },
});

registerFamilySend({
  family: 'chia',
  unit: 'mojos',
  signingChains: [CHIA_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareChia(a as unknown as ChiaAdapter, intent, account.address, {});
    return { ...r, unsigned: ChiaTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => chiaApprovalValid(a as unknown as ChiaAdapter, ChiaTx.parse(tx)),
  expiredReason: 'The coin was spent; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastChia(a as unknown as ChiaAdapter, ChiaTx.parse(tx), raw),
  status: (a, tx, hash) => chiaTransferStatus(a as unknown as ChiaAdapter, ChiaTx.parse(tx), hash),
  form: {
    validate: (to) => isValidChiaAddress(to.trim(), chiaNetworkPrefix(CHIA_TESTNET)),
    normalize: (to) => to.trim(),
    invalid: 'Not a Chia testnet address (txch1…)',
    placeholder: 'txch1…',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'One Chia transfer spends one coin; change returns to you. Chia has no transaction hash — the spent coin id tracks the transfer.',
  },
});

registerFamilySend({
  family: 'fuel',
  unit: 'base',
  signingChains: [FUEL_SEPOLIA],
  prepare: async (a, intent, account) => {
    const r = await prepareFuel(a as unknown as FuelAdapter, intent, account.address);
    return { ...r, unsigned: FuelTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => fuelApprovalValid(a as unknown as FuelAdapter, FuelTx.parse(tx)),
  expiredReason: 'The transaction passed its expiration block; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastFuel(a as unknown as FuelAdapter, FuelTx.parse(tx), raw),
  status: (a, tx, hash) => fuelTransferStatus(a as unknown as FuelAdapter, FuelTx.parse(tx), hash),
  form: {
    validate: (to) => isValidFuelAddress(to.trim()),
    normalize: (to) => to.trim().toLowerCase(),
    invalid: 'Not a Fuel address (0x + 64 hex)',
    placeholder: '0x63520e389b3e28d9af866d60fc41b6753a4450da0962633143ba5924077fdb28',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'Fuel is UTXO-based: the wallet selects coins and returns change to you. The shown fee is the worst case; the settled fee is lower and the difference comes back.',
  },
});

registerFamilySend({
  family: 'aelf',
  unit: 'elves',
  signingChains: [AELF_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareAelf(a as unknown as AelfAdapter, intent, account.address);
    return { ...r, unsigned: AelfTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => aelfApprovalValid(a as unknown as AelfAdapter, AelfTx.parse(tx)),
  expiredReason: 'The reference block went stale; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastAelf(a as unknown as AelfAdapter, AelfTx.parse(tx), raw),
  status: (a, tx, hash) => aelfTransferStatus(a as unknown as AelfAdapter, AelfTx.parse(tx), hash),
  form: {
    validate: (to) => isValidAelfAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not an aelf address (base58check)',
    placeholder: '2QCi3Fy1QXZKFmP6tSBtxCXsaztNzeiDfNgWTamcsj428v4cPZ',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'aelf transactions reference a recent block and go stale within a few minutes; sign and broadcast promptly.',
  },
});

registerFamilySend({
  family: 'starcoin',
  unit: 'nano',
  signingChains: [STARCOIN_BARNARD],
  prepare: async (a, intent, account) => {
    const r = await prepareStarcoin(a as unknown as StarcoinAdapter, intent, account.address);
    return { ...r, unsigned: StarcoinTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    starcoinApprovalValid(a as unknown as StarcoinAdapter, StarcoinTx.parse(tx)),
  expiredReason: 'The transaction expired; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastStarcoin(a as unknown as StarcoinAdapter, StarcoinTx.parse(tx), raw),
  status: (a, tx, hash) =>
    starcoinTransferStatus(a as unknown as StarcoinAdapter, StarcoinTx.parse(tx), hash),
  form: {
    validate: (to) => isValidStarcoinAddress(to.trim().toLowerCase()),
    normalize: (to) => to.trim().toLowerCase(),
    invalid: 'Not a Starcoin address (0x + 32 hex)',
    placeholder: '0xe61b780ad0935f3363bc7fce64edbdad',
    maxUnits: 340_282_366_920_938_463_463_374_607_431_768_211_455n,
    note: 'Transfers run on the Barnard testnet only and expire 30 minutes after preparation. Barnard endpoints omit CORS headers, so sending needs the desktop app.',
  },
});

registerFamilySend({
  family: 'obyte',
  unit: 'bytes',
  signingChains: [OBYTE_TESTNET],
  prepare: async (a, intent, account) => {
    const pubkey = base64Encode(
      Uint8Array.from(account.publicKeyHex.match(/[0-9a-f]{2}/gi)!.map((h) => parseInt(h, 16))),
    );
    const r = await prepareObyte(a as unknown as ObyteAdapter, intent, account.address, pubkey);
    return { ...r, unsigned: ObyteTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => obyteApprovalValid(a as unknown as ObyteAdapter, ObyteTx.parse(tx)),
  expiredReason: 'The prepared unit went stale; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastObyte(a as unknown as ObyteAdapter, ObyteTx.parse(tx), raw),
  status: (a, tx, hash) =>
    obyteTransferStatus(a as unknown as ObyteAdapter, ObyteTx.parse(tx), hash),
  form: {
    validate: (to) => isValidObyteAddress(to.trim().toUpperCase()),
    normalize: (to) => to.trim().toUpperCase(),
    invalid: 'Not an Obyte address (32 uppercase base32 characters)',
    placeholder: 'CVCANIS3HHUKVXEOL3IZR4N6V3O2UB3B',
    maxUnits: 9_000_000_000_000_000n,
    note: "The fee equals the unit's storage size in bytes; the first send from a new address also publishes your public key and costs ~90 bytes more. Do not reuse a prepared transfer after 24 hours.",
  },
});

/** Either Chromia shape: a transfer (`uchr`) or the one-time account registration. */
const chromiaUnsigned = (tx: object) =>
  'uchr' in tx ? ChromiaTx.parse(tx) : ChromiaRegisterTx.parse(tx);

registerFamilySend({
  family: 'chromia',
  unit: 'uchr',
  signingChains: [CHROMIA_TESTNET],
  matches: (tx) => 'register' in tx && 'signer' in tx,
  activation: {
    label: 'register',
    title:
      'Create the FT4 account for this id and claim the CHR already sent to it; the one-time registration waits in the approval queue until you sign it',
    needed: (holding) => holding.notice === CHROMIA_UNREGISTERED_NOTICE,
    proposed: 'Account registration proposed; approve it to claim the pending CHR',
  },
  prepare: async (a, intent, account) => {
    if (isActivationIntent(intent, account)) {
      const r = await prepareChromiaRegistration(
        a as unknown as ChromiaAdapter,
        account.address,
        account.publicKeyHex,
      );
      return { ...r, unsigned: ChromiaRegisterTx.parse(r.unsigned) };
    }
    const r = await prepareChromia(
      a as unknown as ChromiaAdapter,
      intent,
      account.address,
      account.publicKeyHex,
    );
    return { ...r, unsigned: ChromiaTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    chromiaApprovalValid(a as unknown as ChromiaAdapter, chromiaUnsigned(tx)),
  expiredReason: 'The sender account changed; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastChromia(a as unknown as ChromiaAdapter, chromiaUnsigned(tx), raw),
  status: (a, tx, hash) =>
    chromiaTransferStatus(a as unknown as ChromiaAdapter, chromiaUnsigned(tx), hash),
  form: {
    validate: (to) => isValidChromiaAddress(to.trim().toLowerCase()),
    normalize: (to) => to.trim().toLowerCase(),
    invalid: 'Not a Chromia account id (64 lowercase hex)',
    placeholder: '40e60c2bc957f0a754f7aeb0cc3da1a210c29b3feddbc7997f5aceb48aeee122',
    maxUnits: 1_000_000_000_000_000n,
    note: 'The recipient address is an FT4 account id (64 hex), not a public key. Sending to an unregistered id is fine: the transfer stays pending and the recipient claims it with a one-time registration.',
  },
});

registerFamilySend({
  family: 'keeta',
  unit: 'attoKta',
  signingChains: [KEETA_TEST],
  prepare: async (a, intent, account) => {
    const r = await prepareKeeta(a as unknown as KeetaAdapter, intent, account.address);
    return { ...r, unsigned: KeetaTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => keetaApprovalValid(a as unknown as KeetaAdapter, KeetaTx.parse(tx)),
  expiredReason: 'The account head moved; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastKeeta(a as unknown as KeetaAdapter, KeetaTx.parse(tx), raw),
  status: (a, tx, hash) =>
    keetaTransferStatus(a as unknown as KeetaAdapter, KeetaTx.parse(tx), hash),
  form: {
    validate: (to) => isValidKeetaAddress(to.trim().toLowerCase()),
    normalize: (to) => to.trim().toLowerCase(),
    invalid: 'Not a Keeta address (keeta_ plus 63 base32 characters)',
    placeholder: 'keeta_aabhtptgp345zo5mkwqgffooq4fqoau37tns3tri3fm7fak3c34bpgftsw4yiua',
    maxUnits: 1_000_000_000_000_000_000_000_000_000_000_000_000n,
    note: "Keeta blocks record the sender's current head; if you transact from this account elsewhere before publishing, this transfer must be prepared again.",
  },
});

// Namada's broadcast re-verifies both signatures, which needs the signer's
// public key; only the address travels in the tx, so resolve the account in
// the directory by address at broadcast time.
function namadaSignerPub(from: string): Uint8Array {
  const account = directory
    .getSnapshot()
    .accounts.find((a) => a.address === from && /^[0-9a-f]{64}$/i.test(a.publicKeyHex));
  if (!account) throw new Error('No account in this workspace matches the Namada sender');
  return Uint8Array.from(account.publicKeyHex.match(/[0-9a-f]{2}/gi)!.map((h) => parseInt(h, 16)));
}

registerFamilySend({
  family: 'namada',
  unit: 'namnam',
  signingChains: [NAMADA_HOUSEFIRE],
  prepare: async (a, intent, account) => {
    const pub = Uint8Array.from(
      account.publicKeyHex.match(/[0-9a-f]{2}/gi)!.map((h) => parseInt(h, 16)),
    );
    const r = await prepareNamada(a as unknown as NamadaAdapter, intent, account.address, pub);
    return { ...r, unsigned: NamadaTx.parse(r.unsigned) };
  },
  expiredReason: 'The prepared transfer can no longer land; propose a fresh one',
  broadcast: (a, tx, raw) => {
    const parsed = NamadaTx.parse(tx);
    return broadcastNamada(
      a as unknown as NamadaAdapter,
      parsed,
      raw,
      namadaSignerPub(parsed.from),
    );
  },
  status: (a, tx, hash) =>
    namadaTransferStatus(a as unknown as NamadaAdapter, NamadaTx.parse(tx), hash),
  form: {
    validate: (to) => isValidNamadaAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a Namada address (tnam1...)',
    placeholder: 'tnam1qpfe0prje04hulwjdvsjqtmucpfxpttxyy7v2689',
    maxUnits: 18_446_744_073_709_551_615n,
    note: 'Transfers run on the Housefire testnet only; its public RPCs were unreachable at build time, so sending may be unavailable until a community RPC revives.',
  },
});

registerFamilySend({
  family: 'btcfork',
  unit: 'satoshis',
  signingChains: BTCFORK_SIGNING,
  prepare: async (a, intent, account) => {
    const r = await prepareBtcFork(a as unknown as BtcForkAdapter, intent, account.address);
    return { ...r, unsigned: BtcForkTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) =>
    btcForkApprovalValid(a as unknown as BtcForkAdapter, BtcForkTx.parse(tx)),
  expiredReason: 'An input was spent or the expiry height passed; propose a fresh transfer',
  broadcast: (a, tx, raw) =>
    broadcastBtcFork(a as unknown as BtcForkAdapter, BtcForkTx.parse(tx), raw),
  status: (a, tx, hash) =>
    btcForkTransferStatus(a as unknown as BtcForkAdapter, BtcForkTx.parse(tx), hash),
  form: {
    validate: (to, chainId) => isValidForkAddress(to.trim(), chainId),
    normalize: (to) => to.trim(),
    invalid: 'Not a valid address on this network',
    placeholder: 'yXQsTFfMUkAa7j9TeKQXn8woS8umNDzGPn',
    maxUnits: 2_100_000_000_000_000_000n,
    note: 'Sends run on the testnet only. Zcash and Verus transactions expire about 100 blocks after preparation.',
  },
});

registerFamilySend({
  family: 'gala',
  unit: 'gunits',
  signingChains: [GALA_TESTNET],
  prepare: async (a, intent, account) => {
    const r = await prepareGala(a as unknown as GalaAdapter, intent, account.address);
    return { ...r, unsigned: GalaTx.parse(r.unsigned) };
  },
  approvalValid: async (_a, tx) => galaApprovalValid(GalaTx.parse(tx)),
  expiredReason: 'The prepared transfer passed its expiry; propose a fresh one',
  broadcast: (a, tx, raw) => broadcastGala(a as unknown as GalaAdapter, GalaTx.parse(tx), raw),
  status: (a, tx, hash) => galaTransferStatus(a as unknown as GalaAdapter, GalaTx.parse(tx), hash),
  form: {
    validate: (to) => isValidGalaAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a GalaChain address (eth| plus 40 hex)',
    placeholder: 'eth|8ba1f109551bD432803012645Ac136ddd64DBA72',
    maxUnits: 18_446_744_073_709_551_615n,
    note: 'Transfers run on the GalaChain testnet only, burn 1 GALA as the network fee, and expire 30 minutes after preparation.',
  },
});

registerFamilySend({
  family: 'mixin',
  unit: 'xinat',
  signingChains: [MIXIN_MAINNET],
  prepare: async (a, intent, account) => {
    const r = await prepareMixin(a as unknown as MixinAdapter, intent, account.address);
    return { ...r, unsigned: MixinTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => mixinApprovalValid(a as unknown as MixinAdapter, MixinTx.parse(tx)),
  expiredReason: 'An input was spent or locked; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastMixin(a as unknown as MixinAdapter, MixinTx.parse(tx), raw),
  status: (a, tx, hash) =>
    mixinTransferStatus(a as unknown as MixinAdapter, MixinTx.parse(tx), hash),
  form: {
    validate: (to) => isValidMixinAddress(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a Mixin kernel address (XIN...)',
    placeholder:
      'XIN8AJMgQUD11jZYN9ggbQDqkmozrha3zPEZxEkKxVFBufZpEVMtrR6PjtmgtNAH6jrg8dTUQFb9waqqw9euU7Ea8AC6DEu8',
    maxUnits: 18_446_744_073_709_551_615n,
    note: 'Transfers run on the Mixin main kernel — real XIN, no test network exists. The kernel charges no fee; your inputs must cover the amount and change returns to you.',
  },
});

registerFamilySend({
  family: 'qubic',
  unit: 'qu',
  signingChains: [QUBIC_MAINNET],
  prepare: async (a, intent, account) => {
    const r = await prepareQubic(a as unknown as QubicAdapter, intent, account.address);
    return { ...r, unsigned: QubicTx.parse(r.unsigned) };
  },
  approvalValid: (a, tx) => qubicApprovalValid(a as unknown as QubicAdapter, QubicTx.parse(tx)),
  expiredReason: 'The target tick passed; propose a fresh transfer',
  broadcast: (a, tx, raw) => broadcastQubic(a as unknown as QubicAdapter, QubicTx.parse(tx), raw),
  status: (a, tx, hash) =>
    qubicTransferStatus(a as unknown as QubicAdapter, QubicTx.parse(tx), hash),
  form: {
    validate: (to) => isValidQubicIdentity(to.trim()),
    normalize: (to) => to.trim(),
    invalid: 'Not a Qubic identity (60 uppercase letters)',
    placeholder: 'BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK',
    maxUnits: 9_223_372_036_854_775_807n,
    note: 'Transfers run on Qubic mainnet: real QUBIC, no test network exists. Transfers are fee-free and execute at a target tick about a minute after preparation; if that tick passes unexecuted the transfer is dead and must be prepared again.',
  },
});
