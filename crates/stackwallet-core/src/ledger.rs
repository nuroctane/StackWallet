//! The transaction ledger: every intent, its unsigned and signed forms, the
//! policy decision, and the hash-chained audit log, sealed in the vault as one
//! record so a state change and its audit row are written together or not at
//! all. The functions here are the only way a transaction moves: each checks
//! the lifecycle graph, appends the audit row, and seals before returning.
//!
//! Signing happens here too. Approval re-runs the policy with a fresh context,
//! re-derives the signer from the vault, signs the digest the core computed
//! from its own serialization, and stores the raw bytes. The client only ever
//! broadcasts what the core produced.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::aelf::{self, AelfTx};
use crate::aeternity::{self, AeternityTx};
use crate::alephium::{self, AlephiumTx};
use crate::algorand::{self, AlgorandTx};
use crate::antelope::{self, AntelopeTx};
use crate::aptos::{self, AptosTx};
use crate::audit::{Actor, AuditChain, AuditEntry, AuditEvent};
use crate::bitcoin::{self, BitcoinTx};
use crate::btcfork::{self, BtcForkTx};
use crate::cardano::{self, CardanoTx};
use crate::chia::{self, ChiaTx};
use crate::chromia::{self, ChromiaRegisterTx, ChromiaTx};
use crate::cosmos::{self, CosmosTx};
use crate::ergo::{self, ErgoTx};
use crate::everscale::{self, EverscaleTx};
use crate::evm::{self, EvmTx};
use crate::fuel::{self, FuelTx};
use crate::gala::{self, GalaTx};
use crate::hardware;
use crate::hyperliquid::{self, HyperliquidTx};
use crate::icon::{self, IconTx};
use crate::icp::{self, IcpTx};
use crate::intent::{SignRequest, TxIntent};
use crate::keeta::{self, KeetaTx};
use crate::lifecycle::TxState;
use crate::mixin::{self, MixinTx};
use crate::model::Curve;
use crate::multiversx::{self, MultiversxTx};
use crate::namada::{self, NamadaTx};
use crate::near::{self, NearTx};
use crate::obyte::{self, ObyteTx};
use crate::policy::{self, Decision, Policy, PolicyContext, Window};
use crate::provenance;
use crate::qubic::{self, QubicTx};
use crate::radix::{self, RadixTx};
use crate::solana::{self, SolanaTx};
use crate::stacks::{self, StacksTx};
use crate::starcoin::{self, StarcoinTx};
use crate::starknet::{self, StarknetTx};
use crate::stellar::{self, StellarTx};
use crate::substrate::{self, SubstrateTx};
use crate::sui::{self, SuiTx};
use crate::tezos::{self, TezosTx};
use crate::threshold;
use crate::ton::{self, TonTx};
use crate::tron::{self, TronTx};
use crate::vault::SessionProof;
use crate::vault::{EncryptedVault, Secret, Vault};
use crate::vechain::{self, VechainTx};
use crate::waves::{self, WavesTx};
use crate::xrpl::{self, XrplTx};
use crate::{CoreError, Result};

pub const LEDGER_LABEL: &str = "tx-ledger";
const MAX_TXS: usize = 20_000;
const MAX_POLICIES: usize = 256;
const MAX_NOTE_CHARS: usize = 500;

fn invalid(reason: impl Into<String>) -> CoreError {
    CoreError::Invalid {
        what: "transaction ledger",
        reason: reason.into(),
    }
}

/// Which key signs: a single-key wallet's account at a derivation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signer {
    pub wallet_id: String,
    pub path: String,
    /// The address the UI showed; the core re-derives and must arrive at the same one.
    pub address: String,
}

/// Untagged to keep previously sealed EVM ledgers readable without a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UnsignedTx {
    Evm(EvmTx),
    Solana(SolanaTx),
    Cosmos(CosmosTx),
    Bitcoin(BitcoinTx),
    BtcFork(BtcForkTx),
    Tron(TronTx),
    Substrate(SubstrateTx),
    Stellar(StellarTx),
    Aptos(AptosTx),
    Xrpl(XrplTx),
    Sui(SuiTx),
    Near(NearTx),
    Algorand(AlgorandTx),
    Ton(TonTx),
    Cardano(CardanoTx),
    Antelope(AntelopeTx),
    Mixin(MixinTx),
    Multiversx(MultiversxTx),
    Namada(NamadaTx),
    Qubic(QubicTx),
    Tezos(TezosTx),
    Stacks(StacksTx),
    Vechain(VechainTx),
    Hyperliquid(HyperliquidTx),
    Starknet(StarknetTx),
    Icon(IconTx),
    Everscale(EverscaleTx),
    Waves(WavesTx),
    Radix(RadixTx),
    Icp(IcpTx),
    Keeta(KeetaTx),
    Ergo(ErgoTx),
    Alephium(AlephiumTx),
    Aeternity(AeternityTx),
    Aelf(AelfTx),
    Chia(ChiaTx),
    Chromia(ChromiaTx),
    ChromiaRegister(ChromiaRegisterTx),
    Starcoin(StarcoinTx),
    Fuel(FuelTx),
    Gala(GalaTx),
    Obyte(ObyteTx),
}

impl From<ObyteTx> for UnsignedTx {
    fn from(tx: ObyteTx) -> Self {
        Self::Obyte(tx)
    }
}
impl From<GalaTx> for UnsignedTx {
    fn from(tx: GalaTx) -> Self {
        Self::Gala(tx)
    }
}
impl From<FuelTx> for UnsignedTx {
    fn from(tx: FuelTx) -> Self {
        Self::Fuel(tx)
    }
}
impl From<StarcoinTx> for UnsignedTx {
    fn from(tx: StarcoinTx) -> Self {
        Self::Starcoin(tx)
    }
}
impl From<ChromiaTx> for UnsignedTx {
    fn from(tx: ChromiaTx) -> Self {
        Self::Chromia(tx)
    }
}
impl From<ChromiaRegisterTx> for UnsignedTx {
    fn from(tx: ChromiaRegisterTx) -> Self {
        Self::ChromiaRegister(tx)
    }
}
impl From<ChiaTx> for UnsignedTx {
    fn from(tx: ChiaTx) -> Self {
        Self::Chia(tx)
    }
}
impl From<AelfTx> for UnsignedTx {
    fn from(tx: AelfTx) -> Self {
        Self::Aelf(tx)
    }
}
impl From<AeternityTx> for UnsignedTx {
    fn from(tx: AeternityTx) -> Self {
        Self::Aeternity(tx)
    }
}
impl From<AlephiumTx> for UnsignedTx {
    fn from(tx: AlephiumTx) -> Self {
        Self::Alephium(tx)
    }
}
impl From<ErgoTx> for UnsignedTx {
    fn from(tx: ErgoTx) -> Self {
        Self::Ergo(tx)
    }
}
impl From<KeetaTx> for UnsignedTx {
    fn from(tx: KeetaTx) -> Self {
        Self::Keeta(tx)
    }
}
impl From<IcpTx> for UnsignedTx {
    fn from(tx: IcpTx) -> Self {
        Self::Icp(tx)
    }
}
impl From<RadixTx> for UnsignedTx {
    fn from(tx: RadixTx) -> Self {
        Self::Radix(tx)
    }
}
impl From<WavesTx> for UnsignedTx {
    fn from(tx: WavesTx) -> Self {
        Self::Waves(tx)
    }
}
impl From<EverscaleTx> for UnsignedTx {
    fn from(tx: EverscaleTx) -> Self {
        Self::Everscale(tx)
    }
}
impl From<IconTx> for UnsignedTx {
    fn from(tx: IconTx) -> Self {
        Self::Icon(tx)
    }
}
impl From<StarknetTx> for UnsignedTx {
    fn from(tx: StarknetTx) -> Self {
        Self::Starknet(tx)
    }
}
impl From<HyperliquidTx> for UnsignedTx {
    fn from(tx: HyperliquidTx) -> Self {
        Self::Hyperliquid(tx)
    }
}
impl From<VechainTx> for UnsignedTx {
    fn from(tx: VechainTx) -> Self {
        Self::Vechain(tx)
    }
}
impl From<StacksTx> for UnsignedTx {
    fn from(tx: StacksTx) -> Self {
        Self::Stacks(tx)
    }
}
impl From<TezosTx> for UnsignedTx {
    fn from(tx: TezosTx) -> Self {
        Self::Tezos(tx)
    }
}
impl From<NamadaTx> for UnsignedTx {
    fn from(tx: NamadaTx) -> Self {
        Self::Namada(tx)
    }
}
impl From<MixinTx> for UnsignedTx {
    fn from(tx: MixinTx) -> Self {
        Self::Mixin(tx)
    }
}
impl From<QubicTx> for UnsignedTx {
    fn from(tx: QubicTx) -> Self {
        Self::Qubic(tx)
    }
}
impl From<MultiversxTx> for UnsignedTx {
    fn from(tx: MultiversxTx) -> Self {
        Self::Multiversx(tx)
    }
}
impl From<AntelopeTx> for UnsignedTx {
    fn from(tx: AntelopeTx) -> Self {
        Self::Antelope(tx)
    }
}
impl From<CardanoTx> for UnsignedTx {
    fn from(tx: CardanoTx) -> Self {
        Self::Cardano(tx)
    }
}
impl From<TonTx> for UnsignedTx {
    fn from(tx: TonTx) -> Self {
        Self::Ton(tx)
    }
}
impl From<AlgorandTx> for UnsignedTx {
    fn from(tx: AlgorandTx) -> Self {
        Self::Algorand(tx)
    }
}
impl From<NearTx> for UnsignedTx {
    fn from(tx: NearTx) -> Self {
        Self::Near(tx)
    }
}
impl From<SuiTx> for UnsignedTx {
    fn from(tx: SuiTx) -> Self {
        Self::Sui(tx)
    }
}
impl From<XrplTx> for UnsignedTx {
    fn from(tx: XrplTx) -> Self {
        Self::Xrpl(tx)
    }
}
impl From<AptosTx> for UnsignedTx {
    fn from(tx: AptosTx) -> Self {
        Self::Aptos(tx)
    }
}
impl From<SubstrateTx> for UnsignedTx {
    fn from(tx: SubstrateTx) -> Self {
        Self::Substrate(tx)
    }
}
impl From<StellarTx> for UnsignedTx {
    fn from(tx: StellarTx) -> Self {
        Self::Stellar(tx)
    }
}
impl From<TronTx> for UnsignedTx {
    fn from(tx: TronTx) -> Self {
        Self::Tron(tx)
    }
}
impl From<EvmTx> for UnsignedTx {
    fn from(tx: EvmTx) -> Self {
        Self::Evm(tx)
    }
}
impl From<SolanaTx> for UnsignedTx {
    fn from(tx: SolanaTx) -> Self {
        Self::Solana(tx)
    }
}
impl From<CosmosTx> for UnsignedTx {
    fn from(tx: CosmosTx) -> Self {
        Self::Cosmos(tx)
    }
}
impl UnsignedTx {
    /// The curve a threshold group signs this transaction with. Families with
    /// no threshold path report ECDSA, which no group holds.
    fn threshold_curve(&self) -> Curve {
        match self {
            Self::Solana(_) => Curve::Ed25519,
            Self::Bitcoin(_) => Curve::Secp256k1Tr,
            _ => Curve::Secp256k1,
        }
    }
    fn check_matches_intent(&self, intent: &TxIntent) -> Result<()> {
        match self {
            Self::Evm(tx) => evm::check_matches_intent(tx, intent),
            Self::Solana(tx) => tx.check_matches_intent(intent),
            Self::Cosmos(tx) => tx.check_matches_intent(intent),
            Self::Bitcoin(tx) => tx.check_matches_intent(intent),
            Self::BtcFork(tx) => tx.check_matches_intent(intent),
            Self::Tron(tx) => tx.check_matches_intent(intent),
            Self::Substrate(tx) => tx.check_matches_intent(intent),
            Self::Stellar(tx) => tx.check_matches_intent(intent),
            Self::Aptos(tx) => tx.check_matches_intent(intent),
            Self::Xrpl(tx) => tx.check_matches_intent(intent),
            Self::Sui(tx) => tx.check_matches_intent(intent),
            Self::Near(tx) => tx.check_matches_intent(intent),
            Self::Algorand(tx) => tx.check_matches_intent(intent),
            Self::Ton(tx) => tx.check_matches_intent(intent),
            Self::Cardano(tx) => tx.check_matches_intent(intent),
            Self::Antelope(tx) => tx.check_matches_intent(intent),
            Self::Mixin(tx) => tx.check_matches_intent(intent),
            Self::Multiversx(tx) => tx.check_matches_intent(intent),
            Self::Namada(tx) => tx.check_matches_intent(intent),
            Self::Qubic(tx) => tx.check_matches_intent(intent),
            Self::Tezos(tx) => tx.check_matches_intent(intent),
            Self::Stacks(tx) => tx.check_matches_intent(intent),
            Self::Vechain(tx) => tx.check_matches_intent(intent),
            Self::Hyperliquid(tx) => tx.check_matches_intent(intent),
            Self::Starknet(tx) => tx.check_matches_intent(intent),
            Self::Icon(tx) => tx.check_matches_intent(intent),
            Self::Everscale(tx) => tx.check_matches_intent(intent),
            Self::Waves(tx) => tx.check_matches_intent(intent),
            Self::Radix(tx) => tx.check_matches_intent(intent),
            Self::Icp(tx) => tx.check_matches_intent(intent),
            Self::Keeta(tx) => tx.check_matches_intent(intent),
            Self::Ergo(tx) => tx.check_matches_intent(intent),
            Self::Alephium(tx) => tx.check_matches_intent(intent),
            Self::Aeternity(tx) => tx.check_matches_intent(intent),
            Self::Aelf(tx) => tx.check_matches_intent(intent),
            Self::Chia(tx) => tx.check_matches_intent(intent),
            Self::Chromia(tx) => tx.check_matches_intent(intent),
            Self::ChromiaRegister(tx) => tx.check_matches_intent(intent),
            Self::Starcoin(tx) => tx.check_matches_intent(intent),
            Self::Fuel(tx) => tx.check_matches_intent(intent),
            Self::Gala(tx) => tx.check_matches_intent(intent),
            Self::Obyte(tx) => tx.check_matches_intent(intent),
        }
    }
    fn curve(&self) -> Curve {
        match self {
            Self::Evm(_)
            | Self::Cosmos(_)
            | Self::Bitcoin(_)
            | Self::Tron(_)
            | Self::Xrpl(_)
            | Self::Antelope(_)
            | Self::Stacks(_)
            | Self::Vechain(_)
            | Self::Hyperliquid(_)
            | Self::Starknet(_)
            | Self::Icon(_)
            | Self::Icp(_)
            | Self::Ergo(_)
            | Self::Alephium(_)
            | Self::Fuel(_)
            | Self::Aelf(_)
            | Self::Obyte(_)
            | Self::Chromia(_)
            | Self::ChromiaRegister(_)
            | Self::Keeta(_)
            | Self::BtcFork(_)
            | Self::Gala(_) => Curve::Secp256k1,
            Self::Solana(_)
            | Self::Substrate(_)
            | Self::Stellar(_)
            | Self::Aptos(_)
            | Self::Sui(_)
            | Self::Near(_)
            | Self::Algorand(_)
            | Self::Ton(_)
            | Self::Cardano(_)
            | Self::Multiversx(_)
            | Self::Everscale(_)
            | Self::Waves(_)
            | Self::Radix(_)
            | Self::Aeternity(_)
            | Self::Chia(_)
            | Self::Starcoin(_)
            | Self::Namada(_)
            | Self::Mixin(_)
            | Self::Qubic(_)
            | Self::Tezos(_) => Curve::Ed25519,
        }
    }
}
impl From<BtcForkTx> for UnsignedTx {
    fn from(tx: BtcForkTx) -> Self {
        Self::BtcFork(tx)
    }
}
impl From<BitcoinTx> for UnsignedTx {
    fn from(tx: BitcoinTx) -> Self {
        Self::Bitcoin(tx)
    }
}

fn check_bitcoin_reservations(ledger: &Ledger, id: &str, unsigned: &UnsignedTx) -> Result<()> {
    let UnsignedTx::Bitcoin(tx) = unsigned else {
        return Ok(());
    };
    let wallet = &ledger.txs[ledger.index(id)?].intent.wallet_id;
    if let Some(replaced) = &tx.replaces {
        let original = ledger
            .txs
            .iter()
            .find(|t| &t.id == replaced)
            .ok_or_else(|| invalid("the replaced transaction is not in this ledger"))?;
        let Some(UnsignedTx::Bitcoin(old)) = &original.unsigned else {
            return Err(invalid("only a Bitcoin transfer can be replaced by one"));
        };
        if &original.intent.wallet_id != wallet
            || original.raw_signed_hex.is_none()
            || !matches!(original.state, TxState::Broadcast | TxState::Pending)
        {
            return Err(invalid(
                "only this wallet's sent, unconfirmed transfer can be replaced",
            ));
        }
        tx.check_replaces(old)?;
    }
    for other in &ledger.txs {
        if other.id == id
            || (other.raw_signed_hex.is_none()
                && matches!(
                    other.state,
                    TxState::Denied | TxState::Rejected | TxState::Failed | TxState::Expired
                ))
        {
            continue;
        }
        let Some(UnsignedTx::Bitcoin(reserved)) = &other.unsigned else {
            continue;
        };
        if !reserved.inputs.iter().any(|a| {
            tx.inputs
                .iter()
                .any(|b| a.txid == b.txid && a.vout == b.vout)
        }) {
            continue;
        }
        // A replacement conflicts with what is already on the network by
        // design; it must never race another transfer still being approved.
        let on_network = matches!(
            other.state,
            TxState::Broadcast | TxState::Pending | TxState::Replaced | TxState::Dropped
        );
        if tx.replaces.is_some() && on_network && reserved.from == tx.from {
            continue;
        }
        return Err(invalid(
            "Bitcoin input is reserved by another active or signed transfer",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxRecord {
    pub id: String,
    pub intent: TxIntent,
    pub state: TxState,
    pub signer: Option<Signer>,
    pub unsigned: Option<UnsignedTx>,
    /// Adapter simulation, kept verbatim for the approval screen.
    pub simulation: Option<serde_json::Value>,
    pub simulation_ok: Option<bool>,
    pub decision: Option<Decision>,
    pub raw_signed_hex: Option<String>,
    pub hash: Option<String>,
    pub error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ledger {
    #[serde(default)]
    pub txs: Vec<TxRecord>,
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

impl Ledger {
    /// The audit chain must verify, and every transaction's state must be the
    /// last state the chain recorded for it: a record cannot drift from its log.
    pub fn validate(&self) -> Result<()> {
        if self.txs.len() > MAX_TXS || self.policies.len() > MAX_POLICIES {
            return Err(invalid("too many records"));
        }
        AuditChain::from_entries(self.audit.clone())?;
        let mut last: BTreeMap<&str, TxState> = BTreeMap::new();
        for e in &self.audit {
            match &e.event {
                AuditEvent::TxProposed { tx_id, .. } => {
                    last.insert(tx_id, TxState::Draft);
                }
                AuditEvent::TxTransition { tx_id, to, .. } => {
                    last.insert(tx_id, *to);
                }
                _ => {}
            }
        }
        let mut ids = HashSet::new();
        for t in &self.txs {
            if !ids.insert(t.id.as_str()) {
                return Err(invalid(format!("transaction {} appears twice", t.id)));
            }
            if last.get(t.id.as_str()) != Some(&t.state) {
                return Err(invalid(format!(
                    "transaction {} is {:?} but its audit trail disagrees",
                    t.id, t.state
                )));
            }
        }
        let mut pids = HashSet::new();
        for p in &self.policies {
            if !pids.insert(p.id.as_str()) {
                return Err(invalid(format!("policy {} appears twice", p.id)));
            }
        }
        Ok(())
    }

    fn index(&self, id: &str) -> Result<usize> {
        self.txs
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| invalid(format!("no transaction {id}")))
    }

    fn chain(&self) -> Result<AuditChain> {
        AuditChain::from_entries(self.audit.clone())
    }

    fn step(
        &mut self,
        i: usize,
        to: TxState,
        note: Option<String>,
        actor: &Actor,
        now_ms: i64,
    ) -> Result<()> {
        let from = self.txs[i].state;
        crate::lifecycle::transition(from, to)?;
        let mut chain = self.chain()?;
        chain.append(
            now_ms,
            actor.clone(),
            AuditEvent::TxTransition {
                tx_id: self.txs[i].id.clone(),
                from,
                to,
                note: note.map(|n| n.chars().take(MAX_NOTE_CHARS).collect()),
            },
        );
        self.audit = chain.entries().to_vec();
        self.txs[i].state = to;
        self.txs[i].updated_at_ms = now_ms;
        Ok(())
    }

    /// Spend reserved or confirmed in each window, pending count, last send.
    pub fn context(
        &self,
        excluding: &str,
        now_ms: i64,
        simulation_ok: Option<bool>,
    ) -> PolicyContext {
        let windows = [
            (Window::H1, 3_600_000i64),
            (Window::H24, 86_400_000),
            (Window::D7, 604_800_000),
            (Window::D30, 2_592_000_000),
        ];
        let mut spent: BTreeMap<Window, u64> = BTreeMap::new();
        let mut pending = 0u32;
        let mut last: Option<i64> = None;
        for t in self.txs.iter().filter(|t| t.id != excluding) {
            if t.state == TxState::Awaiting {
                pending += 1;
            }
            let counts = t.state.reserves_spend() || t.state == TxState::Confirmed;
            if counts {
                last = Some(last.map_or(t.updated_at_ms, |l| l.max(t.updated_at_ms)));
                let usd = t.intent.usd_micros.unwrap_or(0);
                for (w, span) in windows {
                    // Live signatures and proposals reserve allowance until resolved.
                    // Confirmed spending starts at confirmation, never at draft creation.
                    if t.state.reserves_spend() || now_ms.saturating_sub(t.updated_at_ms) <= span {
                        let total = spent.entry(w).or_default();
                        *total = total.saturating_add(usd);
                    }
                }
            }
        }
        PolicyContext {
            now_ms,
            spent_usd_micros: spent,
            pending_proposals: pending,
            last_tx_at_ms: last,
            simulation_ok,
            key_group: None,
        }
    }
}

pub fn load_ledger(vault: &EncryptedVault) -> Result<Ledger> {
    let Some(handle) = vault.handle_for(LEDGER_LABEL) else {
        return Ok(Ledger::default());
    };
    let ledger = vault.with_secret(&handle, &mut |bytes| {
        serde_json::from_slice::<Ledger>(bytes.expose())
            .map_err(|e| invalid(format!("unreadable: {e}")))
    })??;
    ledger.validate()?;
    Ok(ledger)
}

fn save_ledger(vault: &mut EncryptedVault, next: &Ledger) -> Result<()> {
    next.validate()?;
    let current = load_ledger(vault)?;
    // The log only grows: a save that rewrites or drops a row is refused.
    if !next.audit.starts_with(&current.audit) {
        return Err(invalid("the audit log may only be appended to"));
    }
    let bytes = serde_json::to_vec(next).map_err(|e| invalid(e.to_string()))?;
    vault.put(LEDGER_LABEL, Secret::new(bytes))?;
    Ok(())
}

fn device_actor(device_id: &str) -> Actor {
    Actor::Device {
        device_id: device_id.to_owned(),
    }
}

/// Record a new intent as a draft.
pub fn propose(
    vault: &mut EncryptedVault,
    intent: TxIntent,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    if intent.id.is_empty() || intent.id.len() > 128 {
        return Err(invalid("bad transaction id"));
    }
    if intent.chain_id.0.starts_with("solana:") {
        solana::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("cosmos:") {
        cosmos::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("bip122:") {
        bitcoin::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("tron:") {
        tron::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("polkadot:") {
        substrate::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("stellar:") {
        stellar::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("aptos:") {
        aptos::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("xrpl:") {
        xrpl::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("sui:") {
        sui::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("near:") {
        near::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("algorand:") {
        algorand::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("tvm:") {
        ton::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("cip34:") {
        cardano::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("antelope:") {
        antelope::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("mvx:") {
        multiversx::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("tezos:") {
        tezos::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("stacks:") {
        stacks::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("vechain:") {
        vechain::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("hype:") {
        hyperliquid::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("starknet:") {
        starknet::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("icon:") {
        icon::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("ever:") || intent.chain_id.0.starts_with("venom:") {
        everscale::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("waves:") {
        waves::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("radix:") {
        radix::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("icp:") {
        icp::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("ergo:") {
        ergo::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("alephium:") {
        alephium::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("aet:") {
        aeternity::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("chia:") {
        chia::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("fuel:") {
        fuel::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("aelf:") {
        aelf::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("starcoin:") {
        starcoin::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("obyte:") {
        obyte::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("chromia:") {
        chromia::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("keeta:") {
        keeta::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("namada:") {
        namada::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("btcfork:") {
        btcfork::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("gala:") {
        gala::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("mixin:") {
        mixin::check_chain(&intent.chain_id.0)?;
    } else if intent.chain_id.0.starts_with("qubic:") {
        qubic::check_chain(&intent.chain_id.0)?;
    } else {
        evm::check_chain(&intent.chain_id.0)?;
    }
    let mut ledger = load_ledger(vault)?;
    if ledger.txs.iter().any(|t| t.id == intent.id) {
        return Err(invalid(format!("transaction {} exists", intent.id)));
    }
    let mut chain = ledger.chain()?;
    chain.append(
        now_ms,
        device_actor(device_id),
        AuditEvent::TxProposed {
            tx_id: intent.id.clone(),
            wallet_id: intent.wallet_id.clone(),
            chain_id: intent.chain_id.0.clone(),
        },
    );
    ledger.audit = chain.entries().to_vec();
    let rec = TxRecord {
        id: intent.id.clone(),
        intent,
        state: TxState::Draft,
        signer: None,
        unsigned: None,
        simulation: None,
        simulation_ok: None,
        decision: None,
        raw_signed_hex: None,
        hash: None,
        error: None,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    ledger.txs.push(rec.clone());
    save_ledger(vault, &ledger)?;
    Ok(rec)
}

fn signer_address(
    vault: &EncryptedVault,
    signer: &Signer,
    unsigned: &UnsignedTx,
) -> Result<String> {
    // Bitcoin sighashes do not carry a network ID; refuse mainnet coin derivations.
    if matches!(unsigned, UnsignedTx::Bitcoin(_)) && !signer.path.starts_with("m/84'/1'/") {
        return Err(invalid(
            "Signet signing requires a testnet BIP84 derivation path",
        ));
    }
    // Bitcoin-fork sighashes and TVM external messages are network-agnostic too:
    // a "testnet" transaction signed by a mainnet-coin-type key is a valid
    // mainnet spend from the same address, so those keys never sign here.
    if matches!(unsigned, UnsignedTx::BtcFork(_) | UnsignedTx::Everscale(_))
        && !signer.path.starts_with("m/44'/1'/")
    {
        return Err(invalid(
            "testnet signing requires a testnet (coin type 1) derivation path",
        ));
    }
    if matches!(unsigned, UnsignedTx::Cardano(_)) {
        let account = provenance::cardano_account(&signer.path)
            .ok_or_else(|| invalid("Cardano signs from a CIP-1852 payment path"))?;
        let keys = provenance::cardano_keys(vault, &signer.wallet_id, account)?;
        return cardano::address(&keys.public());
    }
    let key = provenance::signing_key(vault, &signer.wallet_id, unsigned.curve(), &signer.path)?;
    match unsigned {
        UnsignedTx::Solana(_) => Ok(bs58::encode(&key.public).into_string()),
        UnsignedTx::Cosmos(_) => cosmos::address(&key.public),
        UnsignedTx::Bitcoin(_) => bitcoin::address(&key.public),
        UnsignedTx::Tron(_) => tron::address(&key.public),
        UnsignedTx::Substrate(_) => substrate::address(&key.public),
        UnsignedTx::Stellar(_) => stellar::address(&key.public),
        UnsignedTx::Aptos(_) => aptos::address(&key.public),
        UnsignedTx::Xrpl(_) => xrpl::address(&key.public),
        UnsignedTx::Sui(_) => sui::address(&key.public),
        UnsignedTx::Near(_) => near::address(&key.public),
        UnsignedTx::Algorand(_) => algorand::address(&key.public),
        UnsignedTx::Ton(_) => ton::address(&key.public),
        UnsignedTx::Antelope(_) => antelope::address(&key.public),
        UnsignedTx::Multiversx(_) => multiversx::address(&key.public),
        UnsignedTx::Tezos(_) => tezos::address(&key.public),
        UnsignedTx::Stacks(_) => stacks::address(&key.public),
        UnsignedTx::Vechain(_) => vechain::address(&key.public),
        UnsignedTx::Hyperliquid(_) => hyperliquid::address(&key.public),
        // The account address comes from the ground Stark key, not the SEC1 point.
        UnsignedTx::Starknet(_) => starknet::address_from_secret(key.secret()),
        UnsignedTx::Icon(_) => icon::address(&key.public),
        UnsignedTx::Everscale(_) => everscale::address(&key.public),
        // The Waves address comes from the axolotl key, not the ed25519 point.
        UnsignedTx::Waves(_) => waves::address_from_secret(key.secret()),
        UnsignedTx::Radix(_) => radix::address(&key.public),
        UnsignedTx::Icp(_) => icp::address(&key.public),
        UnsignedTx::Ergo(_) => ergo::address(&key.public),
        UnsignedTx::Alephium(_) => alephium::address(&key.public),
        UnsignedTx::Fuel(_) => fuel::address(&key.public),
        UnsignedTx::Aelf(_) => aelf::address(&key.public),
        UnsignedTx::Obyte(_) => obyte::address(&key.public),
        UnsignedTx::Chromia(_) | UnsignedTx::ChromiaRegister(_) => chromia::address(&key.public),
        UnsignedTx::Keeta(_) => Ok(keeta::address(&key.public)?),
        UnsignedTx::Namada(_) => Ok(namada::address(&key.public)?),
        UnsignedTx::BtcFork(tx) => Ok(btcfork::address(&tx.chain_id, &key.public)?),
        UnsignedTx::Gala(_) => Ok(gala::address(&key.public)?),
        UnsignedTx::Mixin(_) => Ok(mixin::address(&mixin::public_from_secret(key.secret()))?),
        UnsignedTx::Qubic(_) => Ok(qubic::address(&qubic::public_key(key.secret())?)?),
        UnsignedTx::Aeternity(_) => aeternity::address(&key.public),
        UnsignedTx::Chia(_) => chia::address(&key.public),
        UnsignedTx::Starcoin(_) => starcoin::address(&key.public),
        UnsignedTx::Cardano(_) => Err(invalid("Cardano keys take the CIP-1852 route")),
        UnsignedTx::Evm(_) => Ok(evm::checksum_address(&evm::address_from_public(
            &key.public,
        )?)),
    }
}

/// Attach the adapter's unsigned transaction and simulation (Draft → Simulated).
/// Refused unless the transaction does exactly what the intent says and the
/// signer derives to the address the user saw.
#[allow(clippy::too_many_arguments)]
pub fn attach(
    vault: &mut EncryptedVault,
    tx_id: &str,
    signer: Signer,
    unsigned: impl Into<UnsignedTx>,
    simulation: serde_json::Value,
    simulation_ok: bool,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let unsigned = unsigned.into();
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if signer.wallet_id != ledger.txs[i].intent.wallet_id {
        return Err(invalid("signer wallet differs from the intent"));
    }
    unsigned.check_matches_intent(&ledger.txs[i].intent)?;
    check_bitcoin_reservations(&ledger, tx_id, &unsigned)?;
    let derived = if provenance::has_single_key(vault, &signer.wallet_id) {
        signer_address(vault, &signer, &unsigned)?
    } else {
        // A hardware account signs as the address its device registered; a
        // threshold wallet as its group key.
        match &unsigned {
            UnsignedTx::Evm(_) => hardware::lookup(vault, &signer.wallet_id, &signer.path)?
                .map(|acc| acc.address)
                .ok_or_else(|| {
                    invalid("no key and no registered hardware account for this signer")
                })?,
            UnsignedTx::Solana(_) | UnsignedTx::Bitcoin(_) => {
                threshold::lookup(vault, &signer.wallet_id)?
                    .filter(|acc| acc.curve == unsigned.threshold_curve())
                    .map(|acc| acc.address)
                    .ok_or_else(|| invalid("no key and no threshold share for this signer"))?
            }
            _ => {
                return Err(invalid(
                    "external signing covers EVM hardware and Solana/Bitcoin threshold wallets",
                ))
            }
        }
    };
    let matches = match &unsigned {
        UnsignedTx::Evm(_) => evm::parse_address(&derived)? == evm::parse_address(&signer.address)?,
        UnsignedTx::Solana(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Cosmos(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Bitcoin(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Tron(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Substrate(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Stellar(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Aptos(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Xrpl(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Sui(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Near(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Algorand(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Ton(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Cardano(tx) => derived == signer.address && tx.from == derived,
        // An Antelope account is an on-chain name a key controls through its permission; the
        // chain enforces that link, the core binds the key.
        UnsignedTx::Antelope(tx) => derived == signer.address && tx.public_key == derived,
        UnsignedTx::Multiversx(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Tezos(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Stacks(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Vechain(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Hyperliquid(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Starknet(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Icon(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Everscale(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Waves(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Radix(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Icp(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Ergo(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Alephium(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Fuel(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Aelf(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Obyte(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Chromia(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::ChromiaRegister(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Keeta(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Namada(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::BtcFork(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Gala(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Mixin(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Qubic(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Aeternity(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Chia(tx) => derived == signer.address && tx.from == derived,
        UnsignedTx::Starcoin(tx) => derived == signer.address && tx.from == derived,
    };
    if !matches {
        return Err(invalid(format!(
            "the key at {} is {derived}, not {}",
            signer.path, signer.address
        )));
    }
    if let UnsignedTx::Evm(tx) = &unsigned {
        if let Some(to) = evm::swap_recipient(tx, &ledger.txs[i].intent)? {
            if to != evm::parse_address(&derived)? {
                return Err(invalid("a swap must pay out to the signing account"));
            }
        }
    }
    let actor = device_actor(device_id);
    ledger.step(
        i,
        TxState::Simulated,
        (!simulation_ok).then(|| "simulation failed".to_owned()),
        &actor,
        now_ms,
    )?;
    let t = &mut ledger.txs[i];
    t.signer = Some(Signer {
        address: derived,
        ..signer
    });
    t.unsigned = Some(unsigned);
    t.simulation = Some(simulation);
    t.simulation_ok = Some(simulation_ok);
    let out = t.clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Run the policies (Simulated → Evaluated → Denied | Awaiting).
pub fn evaluate(
    vault: &mut EncryptedVault,
    tx_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let ctx = ledger.context(tx_id, now_ms, ledger.txs[i].simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &ledger.txs[i].intent, &ctx);
    let actor = device_actor(device_id);
    ledger.step(i, TxState::Evaluated, None, &actor, now_ms)?;
    match &decision {
        Decision::Deny { reasons, .. } => {
            ledger.step(i, TxState::Denied, Some(reasons.join("; ")), &actor, now_ms)?;
        }
        Decision::Allow { .. } => {
            // A human looks at every transaction before it is signed; the queue is that look.
            ledger.step(i, TxState::Awaiting, None, &actor, now_ms)?;
        }
    }
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Approve and sign (Awaiting → Signing → Signed, or → Rejected if the policy
/// no longer allows it). Requires the vault passphrase again.
pub fn approve(
    vault: &mut EncryptedVault,
    tx_id: &str,
    passphrase: &Secret,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    vault.verify_passphrase(passphrase)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Awaiting {
        return Err(invalid(
            "only a transaction awaiting approval can be approved",
        ));
    }
    if let Some(unsigned) = &ledger.txs[i].unsigned {
        check_bitcoin_reservations(&ledger, tx_id, unsigned)?;
    }
    if let Some(signer) = &ledger.txs[i].signer {
        if !provenance::has_single_key(vault, &signer.wallet_id) {
            return Err(invalid(
                "this wallet has no key here; approve it on its device or through its ceremony",
            ));
        }
    }
    // Policies can change while a proposal waits; the signing-time answer wins.
    let ctx = ledger.context(tx_id, now_ms, ledger.txs[i].simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &ledger.txs[i].intent, &ctx);
    if let Decision::Deny { reasons, .. } = &decision {
        let note = format!("policy at signing time: {}", reasons.join("; "));
        ledger.step(i, TxState::Rejected, Some(note), &actor, now_ms)?;
        ledger.txs[i].decision = Some(decision);
        let out = ledger.txs[i].clone();
        save_ledger(vault, &ledger)?;
        return Ok(out);
    }
    if let Decision::Allow {
        required_approvers, ..
    } = &decision
    {
        if required_approvers.iter().any(|r| {
            r.at_least > 1 || (r.at_least == 1 && !r.device_ids.iter().any(|d| d == device_id))
        }) {
            return Err(invalid("this policy needs approvals from other devices"));
        }
    }
    ledger.step(i, TxState::Signing, None, &actor, now_ms)?;
    let t = ledger.txs[i].clone();
    let signed = (|| -> Result<(String, String)> {
        let unsigned = t
            .unsigned
            .as_ref()
            .ok_or_else(|| invalid("no unsigned transaction"))?;
        let signer = t.signer.as_ref().ok_or_else(|| invalid("no signer"))?;
        unsigned.check_matches_intent(&t.intent)?;
        if let UnsignedTx::Cardano(tx) = unsigned {
            if signer_address(vault, signer, unsigned)? != signer.address {
                return Err(invalid("signer key changed since the proposal"));
            }
            let account = provenance::cardano_account(&signer.path)
                .ok_or_else(|| invalid("Cardano signs from a CIP-1852 payment path"))?;
            let keys = provenance::cardano_keys(vault, &signer.wallet_id, account)?;
            return tx.sign(keys.payment.secret());
        }
        let key =
            provenance::signing_key(vault, &signer.wallet_id, unsigned.curve(), &signer.path)?;
        let addr = signer_address(vault, signer, unsigned)?;
        if addr != signer.address {
            return Err(invalid("signer key changed since the proposal"));
        }
        match unsigned {
            UnsignedTx::Evm(tx) => {
                let (v, r, s) = evm::sign_digest(key.secret(), &tx.sighash()?)?;
                let raw = tx.encode_signed(v, &r, &s)?;
                Ok((
                    format!("0x{}", hex::encode(&raw)),
                    format!("0x{}", hex::encode(evm::keccak256(&raw))),
                ))
            }
            UnsignedTx::Solana(tx) => tx.sign(key.secret()),
            UnsignedTx::Cosmos(tx) => tx.sign(key.secret()),
            UnsignedTx::Bitcoin(tx) => tx.sign(key.secret()),
            UnsignedTx::Tron(tx) => tx.sign(key.secret()),
            UnsignedTx::Substrate(tx) => tx.sign(key.secret()),
            UnsignedTx::Stellar(tx) => tx.sign(key.secret()),
            UnsignedTx::Aptos(tx) => tx.sign(key.secret()),
            UnsignedTx::Xrpl(tx) => tx.sign(key.secret()),
            UnsignedTx::Sui(tx) => tx.sign(key.secret()),
            UnsignedTx::Near(tx) => tx.sign(key.secret()),
            UnsignedTx::Algorand(tx) => tx.sign(key.secret()),
            UnsignedTx::Ton(tx) => tx.sign(key.secret()),
            UnsignedTx::Antelope(tx) => tx.sign(key.secret()),
            UnsignedTx::Multiversx(tx) => tx.sign(key.secret()),
            UnsignedTx::Tezos(tx) => tx.sign(key.secret()),
            UnsignedTx::Stacks(tx) => tx.sign(key.secret()),
            UnsignedTx::Vechain(tx) => tx.sign(key.secret()),
            UnsignedTx::Hyperliquid(tx) => tx.sign(key.secret()),
            UnsignedTx::Starknet(tx) => tx.sign(key.secret()),
            UnsignedTx::Icon(tx) => tx.sign(key.secret()),
            UnsignedTx::Everscale(tx) => tx.sign(key.secret()),
            UnsignedTx::Waves(tx) => tx.sign(key.secret()),
            UnsignedTx::Radix(tx) => tx.sign(key.secret()),
            UnsignedTx::Icp(tx) => tx.sign(key.secret()),
            UnsignedTx::Ergo(tx) => tx.sign(key.secret()),
            UnsignedTx::Alephium(tx) => tx.sign(key.secret()),
            UnsignedTx::Fuel(tx) => tx.sign(key.secret()),
            UnsignedTx::Aelf(tx) => tx.sign(key.secret()),
            UnsignedTx::Obyte(tx) => tx.sign(key.secret()),
            UnsignedTx::Chromia(tx) => tx.sign(key.secret()),
            UnsignedTx::ChromiaRegister(tx) => tx.sign(key.secret()),
            UnsignedTx::Keeta(tx) => tx.sign(key.secret()),
            UnsignedTx::Namada(tx) => tx.sign(key.secret()),
            UnsignedTx::BtcFork(tx) => tx.sign(key.secret()),
            UnsignedTx::Gala(tx) => tx.sign(key.secret()),
            UnsignedTx::Mixin(tx) => tx.sign(key.secret()),
            UnsignedTx::Qubic(tx) => tx.sign(key.secret()),
            UnsignedTx::Aeternity(tx) => tx.sign(key.secret()),
            UnsignedTx::Chia(tx) => tx.sign(key.secret()),
            UnsignedTx::Starcoin(tx) => tx.sign(key.secret()),
            UnsignedTx::Cardano(_) => Err(invalid("Cardano keys take the CIP-1852 route")),
        }
    })();
    match signed {
        Ok((raw, hash)) => {
            ledger.step(i, TxState::Signed, None, &actor, now_ms)?;
            ledger.txs[i].raw_signed_hex = Some(raw);
            ledger.txs[i].hash = Some(hash);
        }
        Err(e) => {
            ledger.step(i, TxState::Failed, Some(e.to_string()), &actor, now_ms)?;
            ledger.txs[i].error = Some(e.to_string());
        }
    }
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// First half of a hardware approval: the same checks as [`approve`] (fresh
/// session, signing-time policy, local approver), then Awaiting → Signing and
/// the exact bytes the device must sign. Nothing is signed here.
pub fn begin_external(
    vault: &mut EncryptedVault,
    tx_id: &str,
    session: &SessionProof,
    device_id: &str,
    now_ms: i64,
) -> Result<(TxRecord, String)> {
    vault.verify_session(session, false)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Awaiting {
        return Err(invalid(
            "only a transaction awaiting approval can be approved",
        ));
    }
    let t = ledger.txs[i].clone();
    let (Some(UnsignedTx::Evm(tx)), Some(signer)) = (&t.unsigned, &t.signer) else {
        return Err(invalid("hardware signing is EVM only"));
    };
    let registered = hardware::lookup(vault, &signer.wallet_id, &signer.path)?
        .ok_or_else(|| invalid("this signer is not a registered hardware account"))?;
    if registered.address != signer.address {
        return Err(invalid("hardware account changed since the proposal"));
    }
    evm::check_matches_intent(tx, &t.intent)?;
    let ctx = ledger.context(tx_id, now_ms, t.simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &t.intent, &ctx);
    if let Decision::Deny { reasons, .. } = &decision {
        let note = format!("policy at signing time: {}", reasons.join("; "));
        ledger.step(i, TxState::Rejected, Some(note), &actor, now_ms)?;
        ledger.txs[i].decision = Some(decision);
        let out = ledger.txs[i].clone();
        save_ledger(vault, &ledger)?;
        return Ok((out, String::new()));
    }
    if let Decision::Allow {
        required_approvers, ..
    } = &decision
    {
        if required_approvers.iter().any(|r| {
            r.at_least > 1 || (r.at_least == 1 && !r.device_ids.iter().any(|d| d == device_id))
        }) {
            return Err(invalid("this policy needs approvals from other devices"));
        }
    }
    let payload = format!("0x{}", hex::encode(tx.signing_payload()?));
    ledger.step(
        i,
        TxState::Signing,
        Some("waiting for the hardware device".into()),
        &actor,
        now_ms,
    )?;
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok((out, payload))
}

/// Second half: accept the device's signature only if it recovers, over the
/// core's own sighash, to the registered address. Signing → Signed, or
/// Signing → Failed with the reason when it does not.
pub fn complete_external(
    vault: &mut EncryptedVault,
    tx_id: &str,
    y_parity: u8,
    r: &[u8; 32],
    s: &[u8; 32],
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Signing {
        return Err(invalid(
            "this transaction is not waiting for a device signature",
        ));
    }
    let t = ledger.txs[i].clone();
    let checked = (|| -> Result<(String, String)> {
        let (Some(UnsignedTx::Evm(tx)), Some(signer)) = (&t.unsigned, &t.signer) else {
            return Err(invalid("hardware signing is EVM only"));
        };
        evm::check_matches_intent(tx, &t.intent)?;
        // Devices differ in how they report the recovery bit; (r, s) recovers
        // to the registered address under at most one parity, so try both.
        let sighash = tx.sighash()?;
        let first = y_parity & 1;
        let mut found = None;
        let mut seen = String::new();
        for parity in [first, first ^ 1] {
            match hardware::recover_evm(&sighash, parity, r, s) {
                Ok(addr) if addr == signer.address => {
                    found = Some(parity);
                    break;
                }
                Ok(addr) if seen.is_empty() => seen = addr,
                _ => {}
            }
        }
        let parity = found.ok_or_else(|| {
            invalid(format!(
                "the device signed as {seen}, not {}",
                signer.address
            ))
        })?;
        let raw = tx.encode_signed(parity, r, s)?;
        Ok((
            format!("0x{}", hex::encode(&raw)),
            format!("0x{}", hex::encode(evm::keccak256(&raw))),
        ))
    })();
    match checked {
        Ok((raw, hash)) => {
            ledger.step(i, TxState::Signed, None, &actor, now_ms)?;
            ledger.txs[i].raw_signed_hex = Some(raw);
            ledger.txs[i].hash = Some(hash);
        }
        Err(e) => {
            ledger.step(i, TxState::Failed, Some(e.to_string()), &actor, now_ms)?;
            ledger.txs[i].error = Some(e.to_string());
        }
    }
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// The device refused or went away: Signing → Failed with its reason.
pub fn abort_external(
    vault: &mut EncryptedVault,
    tx_id: &str,
    reason: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if ledger.txs[i].state != TxState::Signing {
        return Err(invalid(
            "this transaction is not waiting for a device signature",
        ));
    }
    let note: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    ledger.step(
        i,
        TxState::Failed,
        Some(note.clone()),
        &device_actor(device_id),
        now_ms,
    )?;
    ledger.txs[i].error = Some(note);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

fn threshold_sender(unsigned: &UnsignedTx) -> Result<&str> {
    match unsigned {
        UnsignedTx::Solana(tx) => Ok(&tx.from),
        UnsignedTx::Bitcoin(tx) if tx.is_taproot()? => Ok(&tx.from),
        _ => Err(invalid(
            "threshold signing covers Solana and Bitcoin Taproot",
        )),
    }
}

/// The bytes a threshold sign ceremony is bound to: the Solana message, or the
/// Bitcoin transaction from which each co-signer derives the input sighashes.
pub fn threshold_payload(unsigned: &UnsignedTx) -> Result<Vec<u8>> {
    threshold_sender(unsigned)?;
    match unsigned {
        UnsignedTx::Solana(tx) => tx.message(),
        UnsignedTx::Bitcoin(tx) => tx.payload(),
        _ => unreachable!("checked by threshold_sender"),
    }
}

/// First half of a threshold approval: the checks of [`approve`], then
/// Awaiting → Signing and the request every share signs. The signature comes
/// back through [`complete_threshold`] once the ceremony has run.
pub fn begin_threshold(
    vault: &mut EncryptedVault,
    tx_id: &str,
    session: &SessionProof,
    device_id: &str,
    now_ms: i64,
) -> Result<(TxRecord, Option<SignRequest>)> {
    vault.verify_session(session, false)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Awaiting {
        return Err(invalid(
            "only a transaction awaiting approval can be approved",
        ));
    }
    let t = ledger.txs[i].clone();
    let (Some(unsigned), Some(signer)) = (&t.unsigned, &t.signer) else {
        return Err(invalid("nothing to sign"));
    };
    let from = threshold_sender(unsigned)?;
    let acc = threshold::lookup(vault, &signer.wallet_id)?
        .ok_or_else(|| invalid("this wallet holds no threshold share here"))?;
    if acc.curve != unsigned.threshold_curve()
        || acc.address != signer.address
        || from != signer.address
    {
        return Err(invalid("the group address changed since the proposal"));
    }
    unsigned.check_matches_intent(&t.intent)?;
    let ctx = ledger.context(tx_id, now_ms, t.simulation_ok);
    let decision = policy::evaluate(&ledger.policies, &t.intent, &ctx);
    if let Decision::Deny { reasons, .. } = &decision {
        let note = format!("policy at signing time: {}", reasons.join("; "));
        ledger.step(i, TxState::Rejected, Some(note), &actor, now_ms)?;
        ledger.txs[i].decision = Some(decision);
        let out = ledger.txs[i].clone();
        save_ledger(vault, &ledger)?;
        return Ok((out, None));
    }
    let message = threshold_payload(unsigned)?;
    let request = SignRequest {
        id: format!("{tx_id}-sign"),
        tx_id: tx_id.to_owned(),
        key_group_id: acc.group.id.clone(),
        curve: acc.curve,
        payload_hash_hex: hex::encode(sha2::Sha256::digest(&message)),
        payload_hex: hex::encode(&message),
    };
    ledger.step(
        i,
        TxState::Signing,
        Some("waiting for the threshold ceremony".into()),
        &actor,
        now_ms,
    )?;
    ledger.txs[i].decision = Some(decision);
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok((out, Some(request)))
}

/// Second half: the aggregate signature must verify against the group key
/// over the core's own message. Signing → Signed, or → Failed with the reason.
pub fn complete_threshold(
    vault: &mut EncryptedVault,
    tx_id: &str,
    signature_hex: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let actor = device_actor(device_id);
    if ledger.txs[i].state != TxState::Signing {
        return Err(invalid("this transaction is not waiting for a ceremony"));
    }
    let t = ledger.txs[i].clone();
    let checked = (|| -> Result<(String, String)> {
        let (Some(unsigned), Some(signer)) = (&t.unsigned, &t.signer) else {
            return Err(invalid("nothing to sign"));
        };
        let acc = threshold::lookup(vault, &signer.wallet_id)?
            .ok_or_else(|| invalid("this wallet holds no threshold share here"))?;
        if acc.curve != unsigned.threshold_curve() || acc.address != threshold_sender(unsigned)? {
            return Err(invalid("the group address changed since the proposal"));
        }
        unsigned.check_matches_intent(&t.intent)?;
        let sig = hex::decode(signature_hex.trim_start_matches("0x"))
            .map_err(|_| invalid("the signature is not hex"))?;
        match unsigned {
            UnsignedTx::Solana(tx) => {
                let sig: [u8; 64] = sig
                    .try_into()
                    .map_err(|_| invalid("a signature is 64 bytes of hex"))?;
                tx.assemble(&sig)
            }
            UnsignedTx::Bitcoin(tx) => tx.assemble_taproot(&sig),
            _ => Err(invalid("threshold signing covers Solana and Bitcoin")),
        }
    })();
    match checked {
        Ok((raw, hash)) => {
            ledger.step(i, TxState::Signed, None, &actor, now_ms)?;
            ledger.txs[i].raw_signed_hex = Some(raw);
            ledger.txs[i].hash = Some(hash);
        }
        Err(e) => {
            ledger.step(i, TxState::Failed, Some(e.to_string()), &actor, now_ms)?;
            ledger.txs[i].error = Some(e.to_string());
        }
    }
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Authorize resending the already approved bytes without creating a new signature or releasing spend.
pub fn retry_broadcast(
    vault: &mut EncryptedVault,
    tx_id: &str,
    passphrase: &Secret,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    vault.verify_passphrase(passphrase)?;
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    let tx = &ledger.txs[i];
    if !matches!(
        tx.state,
        TxState::Signed | TxState::Broadcast | TxState::Pending
    ) {
        return Err(invalid(
            "only an unresolved signed transaction can be retried",
        ));
    }
    if tx.raw_signed_hex.as_ref().is_none_or(|raw| raw.is_empty()) {
        return Err(invalid("no saved signed transaction bytes"));
    }
    let hash = tx
        .hash
        .clone()
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| invalid("no saved transaction hash"))?;
    tx.unsigned
        .as_ref()
        .ok_or_else(|| invalid("no saved unsigned transaction"))?
        .check_matches_intent(&tx.intent)?;
    let ctx = ledger.context(tx_id, now_ms, tx.simulation_ok);
    match policy::evaluate(&ledger.policies, &tx.intent, &ctx) {
        Decision::Deny { reasons, .. } => {
            return Err(invalid(format!("policy at retry: {}", reasons.join("; "))))
        }
        Decision::Allow {
            required_approvers, ..
        } => {
            if required_approvers.iter().any(|r| {
                r.at_least > 1 || (r.at_least == 1 && !r.device_ids.iter().any(|d| d == device_id))
            }) {
                return Err(invalid("this policy needs approvals from other devices"));
            }
        }
    }
    let mut chain = ledger.chain()?;
    chain.append(
        now_ms,
        device_actor(device_id),
        AuditEvent::TxBroadcastRetry {
            tx_id: tx_id.into(),
            hash,
        },
    );
    ledger.audit = chain.entries().to_vec();
    ledger.txs[i].updated_at_ms = now_ms;
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

pub fn reject(
    vault: &mut EncryptedVault,
    tx_id: &str,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    ledger.step(
        i,
        TxState::Rejected,
        Some("rejected by the user".into()),
        &device_actor(device_id),
        now_ms,
    )?;
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Network outcomes the client observed: Broadcast, Pending, Confirmed,
/// Failed, Dropped or Replaced. The lifecycle graph decides what is legal.
pub fn report(
    vault: &mut EncryptedVault,
    tx_id: &str,
    to: TxState,
    note: Option<String>,
    device_id: &str,
    now_ms: i64,
) -> Result<TxRecord> {
    if !matches!(
        to,
        TxState::Broadcast
            | TxState::Pending
            | TxState::Confirmed
            | TxState::Failed
            | TxState::Dropped
            | TxState::Replaced
            | TxState::Expired
    ) {
        return Err(invalid(format!("{to:?} is not a network outcome")));
    }
    let mut ledger = load_ledger(vault)?;
    let i = ledger.index(tx_id)?;
    if to == TxState::Expired
        && !matches!(
            ledger.txs[i].unsigned,
            Some(
                UnsignedTx::Solana(_)
                    | UnsignedTx::Cosmos(_)
                    | UnsignedTx::Tron(_)
                    | UnsignedTx::Substrate(_)
                    | UnsignedTx::Stellar(_)
                    | UnsignedTx::Aptos(_)
                    | UnsignedTx::Xrpl(_)
                    | UnsignedTx::Sui(_)
                    | UnsignedTx::Near(_)
                    | UnsignedTx::Algorand(_)
                    | UnsignedTx::Ton(_)
                    | UnsignedTx::Cardano(_)
                    | UnsignedTx::Antelope(_)
                    | UnsignedTx::Multiversx(_)
                    | UnsignedTx::Tezos(_)
                    | UnsignedTx::Stacks(_)
                    | UnsignedTx::Vechain(_)
                    | UnsignedTx::Hyperliquid(_)
                    | UnsignedTx::Icon(_)
                    | UnsignedTx::Everscale(_)
                    | UnsignedTx::Waves(_)
                    | UnsignedTx::Radix(_)
                    | UnsignedTx::Icp(_)
                    | UnsignedTx::Aeternity(_)
                    | UnsignedTx::Fuel(_)
                    | UnsignedTx::BtcFork(_)
                    | UnsignedTx::Gala(_)
                    | UnsignedTx::Qubic(_)
                    | UnsignedTx::Aelf(_)
                    | UnsignedTx::Starcoin(_)
            )
        )
    {
        return Err(invalid(
            "network expiry requires a transaction with a bounded lifetime",
        ));
    }
    if ledger.txs[i].raw_signed_hex.is_none() && to != TxState::Expired {
        return Err(invalid("nothing was signed for this transaction"));
    }
    ledger.step(i, to, note.clone(), &device_actor(device_id), now_ms)?;
    if matches!(to, TxState::Failed | TxState::Expired) {
        ledger.txs[i].error = note;
    }
    let out = ledger.txs[i].clone();
    save_ledger(vault, &ledger)?;
    Ok(out)
}

/// Replace the policy set; each added, changed or removed policy is audited.
/// Append one event that belongs to no transaction (a signed message).
pub fn append_audit(
    vault: &mut EncryptedVault,
    now_ms: i64,
    actor: Actor,
    event: AuditEvent,
) -> Result<()> {
    let mut ledger = load_ledger(vault)?;
    let mut chain = ledger.chain()?;
    chain.append(now_ms, actor, event);
    ledger.audit = chain.entries().to_vec();
    save_ledger(vault, &ledger)
}

pub fn set_policies(
    vault: &mut EncryptedVault,
    policies: Vec<Policy>,
    device_id: &str,
    now_ms: i64,
) -> Result<()> {
    let mut ledger = load_ledger(vault)?;
    let before: BTreeMap<String, Policy> = ledger
        .policies
        .iter()
        .map(|p| (p.id.clone(), p.clone()))
        .collect();
    let after: BTreeMap<String, Policy> =
        policies.iter().map(|p| (p.id.clone(), p.clone())).collect();
    let mut chain = ledger.chain()?;
    for id in before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if before.get(id) != after.get(id) {
            chain.append(
                now_ms,
                device_actor(device_id),
                AuditEvent::PolicyChanged {
                    policy_id: id.clone(),
                },
            );
        }
    }
    ledger.audit = chain.entries().to_vec();
    ledger.policies = policies;
    save_ledger(vault, &ledger)
}

#[cfg(test)]
mod tests {
    #[test]
    fn retries_keep_original_bytes_state_reservation_and_verified_audit() {
        let mut v = vault();
        to_awaiting(&mut v, "retry");
        let original = approve(&mut v, "retry", &pw(), "d", 4).unwrap();
        for (step, state) in [
            (5, TxState::Signed),
            (7, TxState::Broadcast),
            (9, TxState::Pending),
        ] {
            if state != TxState::Signed {
                report(&mut v, "retry", state, None, "d", step).unwrap();
            }
            let before = load_ledger(&v).unwrap().audit.len();
            let retried = retry_broadcast(&mut v, "retry", &pw(), "d", step + 1).unwrap();
            assert_eq!(retried.state, state);
            assert!(retried.state.reserves_spend());
            assert_eq!(retried.raw_signed_hex, original.raw_signed_hex);
            assert_eq!(retried.hash, original.hash);
            let ledger = load_ledger(&v).unwrap();
            assert_eq!(ledger.audit.len(), before + 1);
            assert!(
                matches!(&ledger.audit.last().unwrap().event, AuditEvent::TxBroadcastRetry { tx_id, hash }
                if tx_id == "retry" && Some(hash) == original.hash.as_ref())
            );
            ledger.validate().unwrap();
        }
        report(&mut v, "retry", TxState::Confirmed, None, "d", 11).unwrap();
        let before = load_ledger(&v).unwrap();
        assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 12).is_err());
        assert_eq!(load_ledger(&v).unwrap(), before);
    }

    #[test]
    fn retry_requires_passphrase_and_current_policy_without_discarding_signed_spend() {
        let mut v = vault();
        to_awaiting(&mut v, "retry");
        assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 4).is_err());
        approve(&mut v, "retry", &pw(), "d", 5).unwrap();
        let before = load_ledger(&v).unwrap();
        assert!(retry_broadcast(&mut v, "retry", &Secret::new(b"wrong".to_vec()), "d", 6).is_err());
        assert_eq!(load_ledger(&v).unwrap(), before);
        for rule in [
            Rule::DestinationDeny {
                addresses: vec![TO.into()],
            },
            Rule::RequireApprovers {
                device_ids: vec!["other".into()],
                at_least: 1,
            },
        ] {
            set_policies(
                &mut v,
                vec![Policy {
                    id: "retry-policy".into(),
                    name: "retry-policy".into(),
                    mode: PolicyMode::Enforce,
                    rules: vec![rule],
                }],
                "d",
                7,
            )
            .unwrap();
            let before = load_ledger(&v).unwrap();
            assert!(retry_broadcast(&mut v, "retry", &pw(), "d", 8).is_err());
            assert_eq!(load_ledger(&v).unwrap(), before);
            assert!(before.txs[0].state.reserves_spend());
        }
    }

    #[test]
    fn live_reservations_do_not_age_out_and_confirmed_spending_uses_confirmation_time() {
        let mut v = vault();
        let mut tx = to_awaiting(&mut v, "old");
        tx.state = TxState::Signed;
        let later = 7_200_001;
        let mut ledger = Ledger {
            txs: vec![tx],
            ..Ledger::default()
        };
        assert_eq!(
            ledger.context("new", later, None).spent_usd_micros[&Window::H1],
            5_000_000
        );
        ledger.txs[0].state = TxState::Confirmed;
        ledger.txs[0].updated_at_ms = later;
        assert_eq!(
            ledger.context("new", later + 1, None).spent_usd_micros[&Window::H1],
            5_000_000
        );
        assert_eq!(
            ledger
                .context("new", later + 3_600_001, None)
                .spent_usd_micros
                .get(&Window::H1),
            None
        );
    }
    use super::*;
    use crate::intent::{Amount, Proposer, TxIntentKind};
    use crate::model::{AssetRef, ChainId};
    use crate::policy::{PolicyMode, Rule};
    use crate::vault::KdfParams;

    const PHRASE: &str = "test test test test test test test test test test test junk";
    const PATH: &str = "m/44'/60'/0'/0/0";
    const ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const TO: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    fn vault() -> EncryptedVault {
        let mut v =
            EncryptedVault::create(&Secret::new(b"pw".to_vec()), KdfParams::MINIMUM).unwrap();
        provenance::import_phrase(&mut v, "w", PHRASE, 0).unwrap();
        v
    }

    fn pw() -> Secret {
        Secret::new(b"pw".to_vec())
    }

    #[test]
    fn signing_an_old_proposal_does_not_open_new_spend_allowance() {
        let mut v = vault();
        set_policies(
            &mut v,
            vec![Policy {
                id: "cap".into(),
                name: "cap".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::SpendCap {
                    window: Window::H1,
                    usd_micros: 5_000_000,
                }],
            }],
            "d",
            0,
        )
        .unwrap();
        assert_eq!(to_awaiting(&mut v, "old").state, TxState::Awaiting);
        let later = 7_200_001;
        assert_eq!(
            approve(&mut v, "old", &pw(), "d", later).unwrap().state,
            TxState::Signed
        );
        propose(&mut v, intent("new", TO, "1000"), "d", later + 1).unwrap();
        attach(
            &mut v,
            "new",
            signer(),
            unsigned(TO, "1000"),
            serde_json::json!({"ok": true}),
            true,
            "d",
            later + 2,
        )
        .unwrap();
        assert_eq!(
            evaluate(&mut v, "new", "d", later + 3).unwrap().state,
            TxState::Denied
        );
        load_ledger(&v).unwrap().validate().unwrap();
    }

    #[test]
    fn bitcoin_inputs_are_reserved_and_the_full_lifecycle_is_audited() {
        let mut v = vault();
        let path = "m/84'/1'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let unsigned = bitcoin::fixture(&key.public);
        let make_intent = |id: &str| {
            let mut i = intent(id, &unsigned.to, &unsigned.amount);
            i.chain_id = ChainId(bitcoin::SIGNET.into());
            i.kind = TxIntentKind::Transfer {
                to: unsigned.to.clone(),
                asset: AssetRef(format!("{}:native", bitcoin::SIGNET)),
                amount: Amount(unsigned.amount.clone()),
            };
            i
        };
        let signer = Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: unsigned.from.clone(),
        };
        let wrong_path = Signer {
            path: "m/84'/0'/0'/0/0".into(),
            ..signer.clone()
        };
        assert!(signer_address(&v, &wrong_path, &UnsignedTx::Bitcoin(unsigned.clone())).is_err());
        propose(&mut v, make_intent("btc"), "d", 1).unwrap();
        attach(
            &mut v,
            "btc",
            signer.clone(),
            unsigned.clone(),
            serde_json::json!({"ok":false}),
            false,
            "d",
            2,
        )
        .unwrap();
        evaluate(&mut v, "btc", "d", 3).unwrap();
        propose(&mut v, make_intent("conflict"), "d", 4).unwrap();
        assert!(attach(
            &mut v,
            "conflict",
            signer.clone(),
            unsigned.clone(),
            serde_json::json!({}),
            false,
            "d",
            5
        )
        .is_err());
        assert!(approve(&mut v, "btc", &Secret::new(b"wrong".to_vec()), "d", 6).is_err());
        let signed = approve(&mut v, "btc", &pw(), "d", 7).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        report(&mut v, "btc", TxState::Broadcast, None, "d", 8).unwrap();
        report(&mut v, "btc", TxState::Pending, None, "d", 9).unwrap();
        assert!(report(&mut v, "btc", TxState::Expired, None, "d", 10).is_err());
        report(&mut v, "btc", TxState::Confirmed, None, "d", 11).unwrap();
        load_ledger(&v).unwrap().validate().unwrap();
    }

    #[test]
    fn a_stuck_bitcoin_transfer_can_be_sped_up_or_cancelled_under_bip125() {
        let mut v = vault();
        let path = "m/84'/1'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let original = bitcoin::fixture(&key.public);
        let signer = Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: original.from.clone(),
        };
        let mut step = 0;
        let mut send = |v: &mut EncryptedVault, id: &str, tx: &BitcoinTx| {
            step += 10;
            let mut i = intent(id, &tx.to, &tx.amount);
            i.chain_id = ChainId(bitcoin::SIGNET.into());
            i.kind = TxIntentKind::Transfer {
                to: tx.to.clone(),
                asset: AssetRef(format!("{}:native", bitcoin::SIGNET)),
                amount: Amount(tx.amount.clone()),
            };
            propose(v, i, "d", step).unwrap();
            attach(
                v,
                id,
                signer.clone(),
                tx.clone(),
                serde_json::json!({}),
                false,
                "d",
                step + 1,
            )
        };
        send(&mut v, "orig", &original).unwrap();
        evaluate(&mut v, "orig", "d", 12).unwrap();

        // Not on the network yet: nothing to replace, and its inputs stay reserved.
        let faster = BitcoinTx {
            fee: "700".into(),
            replaces: Some("orig".into()),
            ..original.clone()
        };
        assert!(send(&mut v, "early", &faster).is_err());
        approve(&mut v, "orig", &pw(), "d", 13).unwrap();
        report(&mut v, "orig", TxState::Broadcast, None, "d", 14).unwrap();
        report(&mut v, "orig", TxState::Pending, None, "d", 15).unwrap();

        // 142 vB bound: +100 sats does not pay the incremental relay fee.
        let timid = BitcoinTx {
            fee: "600".into(),
            ..faster.clone()
        };
        assert!(send(&mut v, "timid", &timid)
            .unwrap_err()
            .to_string()
            .contains("fee rate"));
        // An ordinary send still may not touch the pending inputs.
        assert!(send(&mut v, "plain", &original).is_err());
        let rec = send(&mut v, "faster", &faster).unwrap();
        assert_eq!(rec.state, TxState::Simulated);
        evaluate(&mut v, "faster", "d", 100).unwrap();
        // A second replacement may not race one still being approved.
        let cancel = BitcoinTx {
            to: original.from.clone(),
            amount: "99100".into(),
            fee: "900".into(),
            replaces: Some("orig".into()),
            ..original.clone()
        };
        assert!(send(&mut v, "cancel-early", &cancel).is_err());
        let signed = approve(&mut v, "faster", &pw(), "d", 101).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        report(&mut v, "faster", TxState::Broadcast, None, "d", 102).unwrap();
        report(&mut v, "faster", TxState::Pending, None, "d", 103).unwrap();

        // Cancel the speed-up too: everything back to the sender, one output.
        let cancel = BitcoinTx {
            replaces: Some("faster".into()),
            amount: "98900".into(),
            fee: "1100".into(),
            ..cancel
        };
        let leftover = BitcoinTx {
            amount: "98000".into(),
            ..cancel.clone()
        };
        assert!(leftover.psbt().is_err(), "a cancel leaves no change");
        let unreplaced = BitcoinTx {
            replaces: None,
            ..cancel.clone()
        };
        assert!(unreplaced.psbt().is_err(), "self-payment only as a cancel");
        send(&mut v, "cancel", &cancel).unwrap();
        evaluate(&mut v, "cancel", "d", 200).unwrap();
        let signed = approve(&mut v, "cancel", &pw(), "d", 201).unwrap();
        let raw = hex::decode(&signed.raw_signed_hex.unwrap()[2..]).unwrap();
        let tx: ::bitcoin::Transaction = ::bitcoin::consensus::deserialize(&raw).unwrap();
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 98_900);
        load_ledger(&v).unwrap().validate().unwrap();

        // Replacing a confirmed transfer, or another wallet's, is refused.
        report(&mut v, "cancel", TxState::Broadcast, None, "d", 202).unwrap();
        report(&mut v, "cancel", TxState::Pending, None, "d", 203).unwrap();
        report(&mut v, "cancel", TxState::Confirmed, None, "d", 204).unwrap();
        let late = BitcoinTx {
            fee: "1500".into(),
            amount: "98500".into(),
            replaces: Some("cancel".into()),
            ..cancel.clone()
        };
        assert!(send(&mut v, "late", &late).is_err());
    }

    fn intent(id: &str, to: &str, amount: &str) -> TxIntent {
        TxIntent {
            id: id.into(),
            wallet_id: "w".into(),
            account_id: "a".into(),
            chain_id: ChainId("eip155:11155111".into()),
            proposer: Proposer::Human {
                device_id: "d".into(),
            },
            kind: TxIntentKind::Transfer {
                to: to.into(),
                asset: AssetRef("eip155:11155111:native".into()),
                amount: Amount(amount.into()),
            },
            usd_micros: Some(5_000_000),
            untrusted_destinations: vec![],
            created_at_ms: 0,
        }
    }

    fn unsigned(to: &str, value: &str) -> EvmTx {
        EvmTx {
            chain_id: 11155111,
            nonce: 0,
            max_priority_fee_per_gas: "1000000000".into(),
            max_fee_per_gas: "20000000000".into(),
            gas_limit: 21000,
            to: to.into(),
            value: value.into(),
            data_hex: String::new(),
        }
    }

    fn signer() -> Signer {
        Signer {
            wallet_id: "w".into(),
            path: PATH.into(),
            address: ADDR.into(),
        }
    }

    fn to_awaiting(v: &mut EncryptedVault, id: &str) -> TxRecord {
        propose(v, intent(id, TO, "1000"), "d", 1).unwrap();
        attach(
            v,
            id,
            signer(),
            unsigned(TO, "1000"),
            serde_json::json!({"ok": true}),
            true,
            "d",
            2,
        )
        .unwrap();
        evaluate(v, id, "d", 3).unwrap()
    }

    #[test]
    fn hardware_signatures_must_recover_to_the_registered_address() {
        let mut v = vault();
        let session = SessionProof::Passphrase(pw());
        // The "device" holds the Hardhat key; the vault holds none for wallet "hw".
        let device_key = provenance::signing_key(&v, "w", Curve::Secp256k1, PATH).unwrap();
        hardware::register(&mut v, &session, "hw", PATH, ADDR).unwrap();
        assert!(
            hardware::register(&mut v, &session, "hw", PATH, TO).is_err(),
            "no re-pointing"
        );
        let hw = Signer {
            wallet_id: "hw".into(),
            ..signer()
        };
        for (id, good) in [("ok", true), ("bad", false)] {
            let mut i = intent(id, TO, "1000");
            i.wallet_id = "hw".into();
            propose(&mut v, i, "d", 1).unwrap();
            attach(
                &mut v,
                id,
                hw.clone(),
                unsigned(TO, "1000"),
                serde_json::json!({}),
                true,
                "d",
                2,
            )
            .unwrap();
            assert_eq!(
                evaluate(&mut v, id, "d", 3).unwrap().state,
                TxState::Awaiting
            );
            assert!(approve(&mut v, id, &pw(), "d", 4).is_err());
            assert_eq!(
                load_ledger(&v).unwrap().txs[load_ledger(&v).unwrap().index(id).unwrap()].state,
                TxState::Awaiting
            );
            let (rec, payload) = begin_external(&mut v, id, &session, "d", 5).unwrap();
            assert_eq!(rec.state, TxState::Signing);
            let bytes = hex::decode(payload.trim_start_matches("0x")).unwrap();
            assert_eq!(bytes[0], 0x02, "EIP-1559 typed payload");
            let digest = evm::keccak256(&bytes);
            let secret: [u8; 32] = if good {
                *device_key.secret()
            } else {
                [7u8; 32]
            };
            let (y, r, sig_s) = evm::sign_digest(&secret, &digest).unwrap();
            let done = complete_external(&mut v, id, y, &r, &sig_s, "d", 6).unwrap();
            if good {
                assert_eq!(done.state, TxState::Signed);
                assert!(done.raw_signed_hex.unwrap().starts_with("0x02"));
            } else {
                assert_eq!(done.state, TxState::Failed);
                assert!(done.error.unwrap().contains("the device signed as"));
            }
        }
        // A hardware signer with no registration cannot even be attached.
        let mut i = intent("stray", TO, "1");
        i.wallet_id = "other".into();
        propose(&mut v, i, "d", 1).unwrap();
        let stray = Signer {
            wallet_id: "other".into(),
            ..signer()
        };
        assert!(attach(
            &mut v,
            "stray",
            stray,
            unsigned(TO, "1"),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        load_ledger(&v).unwrap().chain().unwrap().verify().unwrap();
    }

    #[test]
    fn evm_mainnets_are_refused_at_proposal() {
        let mut v = vault();
        for chain in ["eip155:1", "eip155:8453", "eip155:137"] {
            let mut i = intent(chain, TO, "1");
            i.chain_id = ChainId(chain.into());
            i.kind = TxIntentKind::Transfer {
                to: TO.into(),
                asset: AssetRef(format!("{chain}:native")),
                amount: Amount("1".into()),
            };
            let err = propose(&mut v, i, "d", 1).unwrap_err();
            assert!(err.to_string().contains("testnets only"), "{chain}: {err}");
        }
        assert!(load_ledger(&v).unwrap().txs.is_empty());
    }

    fn solana_awaiting(v: &mut EncryptedVault, id: &str) -> TxRecord {
        solana_awaiting_version(v, id, solana::MessageVersion::Legacy)
    }

    fn solana_awaiting_version(
        v: &mut EncryptedVault,
        id: &str,
        message_version: solana::MessageVersion,
    ) -> TxRecord {
        let path = "m/44'/501'/0'/0'";
        let key = provenance::signing_key(v, "w", Curve::Ed25519, path).unwrap();
        let from = bs58::encode(hex::decode(key.public_hex()).unwrap()).into_string();
        let to = bs58::encode([8; 32]).into_string();
        let mut i = intent(id, &to, "1000");
        i.chain_id = ChainId(solana::DEVNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", solana::DEVNET)),
            amount: Amount("1000".into()),
        };
        propose(v, i, "d", 1).unwrap();
        attach(
            v,
            id,
            Signer {
                wallet_id: "w".into(),
                path: path.into(),
                address: from.clone(),
            },
            SolanaTx {
                chain_id: solana::DEVNET.into(),
                from,
                to,
                lamports: "1000".into(),
                recent_blockhash: bs58::encode([9; 32]).into_string(),
                last_valid_block_height: 100,
                message_version,
            },
            serde_json::json!({"ok": true}),
            true,
            "d",
            2,
        )
        .unwrap();
        evaluate(v, id, "d", 3).unwrap()
    }

    #[test]
    fn versioned_solana_signing_and_history_are_audited() {
        let mut v = vault();
        solana_awaiting_version(&mut v, "v0", solana::MessageVersion::V0);
        let signed = approve(&mut v, "v0", &pw(), "d", 4).unwrap();
        let raw = hex::decode(signed.raw_signed_hex.unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 217);
        assert_eq!(raw[65], 0x80);
        report(&mut v, "v0", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "v0", TxState::Pending, None, "d", 6).unwrap();
        let ledger = load_ledger(&v).unwrap();
        ledger.validate().unwrap();
        assert!(matches!(
            ledger.audit.last().unwrap().event,
            AuditEvent::TxTransition {
                to: TxState::Pending,
                ..
            }
        ));
        let bytes = v.to_bytes().unwrap();
        let mut reopened = EncryptedVault::from_bytes(&bytes).unwrap();
        reopened.unlock(&pw()).unwrap();
        assert_eq!(load_ledger(&reopened).unwrap(), ledger);
    }

    #[test]
    fn solana_lifecycle_expiry_and_failure_are_audited() {
        let mut v = vault();
        let t = solana_awaiting(&mut v, "sol");
        assert_eq!(t.state, TxState::Awaiting);
        assert!(approve(&mut v, "sol", &Secret::new(b"wrong".to_vec()), "d", 4).is_err());
        let signed = approve(&mut v, "sol", &pw(), "d", 4).unwrap();
        assert_eq!(signed.state, TxState::Signed);
        let raw = hex::decode(signed.raw_signed_hex.unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 215);
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&raw[69..101].try_into().unwrap()).unwrap();
        key.verify_strict(
            &raw[65..],
            &ed25519_dalek::Signature::from_slice(&raw[1..65]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            bs58::encode(&raw[1..65]).into_string(),
            signed.hash.unwrap()
        );
        report(&mut v, "sol", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "sol", TxState::Pending, None, "d", 6).unwrap();
        report(
            &mut v,
            "sol",
            TxState::Failed,
            Some("on-chain failure".into()),
            "d",
            7,
        )
        .unwrap();
        solana_awaiting(&mut v, "expired");
        let expired = report(
            &mut v,
            "expired",
            TxState::Expired,
            Some("blockhash expired".into()),
            "d",
            8,
        )
        .unwrap();
        assert!(expired.raw_signed_hex.is_none());
        assert!(approve(&mut v, "expired", &pw(), "d", 9).is_err());
        let ledger = load_ledger(&v).unwrap();
        ledger.validate().unwrap();
        assert_eq!(
            ledger.audit.last().unwrap().event,
            AuditEvent::TxTransition {
                tx_id: "expired".into(),
                from: TxState::Awaiting,
                to: TxState::Expired,
                note: Some("blockhash expired".into()),
            }
        );
        let bytes = v.to_bytes().unwrap();
        let mut reopened = EncryptedVault::from_bytes(&bytes).unwrap();
        reopened.unlock(&pw()).unwrap();
        assert_eq!(load_ledger(&reopened).unwrap(), ledger);
    }

    #[test]
    fn solana_policy_rechecks_and_legacy_evm_payloads_survive() {
        let mut v = vault();
        let sol = solana_awaiting(&mut v, "sol");
        set_policies(
            &mut v,
            vec![Policy {
                id: "deny-sol".into(),
                name: "Deny Solana".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::ChainAllow {
                    chain_ids: vec![ChainId("eip155:11155111".into())],
                }],
            }],
            "d",
            4,
        )
        .unwrap();
        assert_eq!(
            approve(&mut v, "sol", &pw(), "d", 5).unwrap().state,
            TxState::Rejected
        );
        let legacy = unsigned(TO, "1000");
        let json = serde_json::to_value(&legacy).unwrap();
        let decoded: UnsignedTx = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<TxRecord>(serde_json::to_value(&sol).unwrap()).unwrap(),
            sol
        );
    }

    #[test]
    fn full_lifecycle_is_audited_and_signed_by_the_core() {
        let mut v = vault();
        let t = to_awaiting(&mut v, "t1");
        assert_eq!(t.state, TxState::Awaiting);
        assert!(approve(&mut v, "t1", &Secret::new(b"no".to_vec()), "d", 4).is_err());
        let t = approve(&mut v, "t1", &pw(), "d", 4).unwrap();
        assert_eq!(t.state, TxState::Signed);
        let raw = t.raw_signed_hex.unwrap();
        assert!(raw.starts_with("0x02"));
        report(&mut v, "t1", TxState::Broadcast, None, "d", 5).unwrap();
        report(&mut v, "t1", TxState::Pending, None, "d", 6).unwrap();
        let t = report(&mut v, "t1", TxState::Confirmed, None, "d", 7).unwrap();
        assert_eq!(t.state, TxState::Confirmed);
        assert!(
            report(&mut v, "t1", TxState::Pending, None, "d", 8).is_err(),
            "no going back"
        );

        let l = load_ledger(&v).unwrap();
        let states: Vec<_> = l
            .audit
            .iter()
            .filter_map(|e| match &e.event {
                AuditEvent::TxTransition { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        use TxState::*;
        assert_eq!(
            states,
            vec![Simulated, Evaluated, Awaiting, Signing, Signed, Broadcast, Pending, Confirmed]
        );
    }

    #[test]
    fn cosmos_expiry_is_audited_and_does_not_change_legacy_lifetimes() {
        let mut v = vault();
        to_awaiting(&mut v, "evm");
        assert!(report(&mut v, "evm", TxState::Expired, None, "d", 4).is_err());
        let path = "m/44'/118'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let from = cosmos::address(&key.public).unwrap();
        let other =
            provenance::signing_key(&v, "w", Curve::Secp256k1, "m/44'/118'/0'/0/1").unwrap();
        let to = cosmos::address(&other.public).unwrap();
        let unsigned = CosmosTx {
            msg: cosmos::CosmosMsg::Send,
            chain_id: cosmos::TESTNET.into(),
            from: from.clone(),
            to: to.clone(),
            amount: "1000".into(),
            public_key_hex: key.public_hex(),
            account_number: "42".into(),
            sequence: "0".into(),
            gas_limit: 100000,
            fee_amount: "2500".into(),
            timeout_height: 123,
        };
        let mut i = intent("cosmos", &to, "1000");
        i.chain_id = ChainId(cosmos::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to,
            asset: AssetRef(format!("{}:native", cosmos::TESTNET)),
            amount: Amount("1000".into()),
        };
        propose(&mut v, i, "d", 5).unwrap();
        attach(
            &mut v,
            "cosmos",
            Signer {
                wallet_id: "w".into(),
                path: path.into(),
                address: from,
            },
            unsigned,
            serde_json::json!({"ok":true}),
            true,
            "d",
            6,
        )
        .unwrap();
        evaluate(&mut v, "cosmos", "d", 7).unwrap();
        assert_eq!(
            approve(&mut v, "cosmos", &pw(), "d", 8).unwrap().state,
            TxState::Signed
        );
        report(&mut v, "cosmos", TxState::Broadcast, None, "d", 9).unwrap();
        report(&mut v, "cosmos", TxState::Pending, None, "d", 10).unwrap();
        assert_eq!(
            report(
                &mut v,
                "cosmos",
                TxState::Expired,
                Some("timeout".into()),
                "d",
                11
            )
            .unwrap()
            .state,
            TxState::Expired
        );
        assert!(approve(&mut v, "cosmos", &pw(), "d", 12).is_err());
        load_ledger(&v).unwrap().validate().unwrap();
    }

    #[test]
    fn tron_nile_transfer_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/195'/0'/0/0";
        let key = provenance::signing_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let from = tron::address(&key.public).unwrap();
        let other =
            provenance::signing_key(&v, "w", Curve::Secp256k1, "m/44'/195'/0'/0/1").unwrap();
        let to = tron::address(&other.public).unwrap();
        let unsigned = TronTx {
            chain_id: tron::NILE.into(),
            from: from.clone(),
            to: to.clone(),
            sun: "1000000".into(),
            ref_block_bytes: "60b9".into(),
            ref_block_hash: "abababababababab".into(),
            expiration: 1_760_000_060_000,
            timestamp: 1_760_000_000_000,
        };
        let mut i = intent("tron", &to, "1000000");
        i.chain_id = ChainId(tron::NILE.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", tron::NILE)),
            amount: Amount("1000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        // The UI's address must be the one the core derives at the path.
        assert!(attach(
            &mut v,
            "tron",
            signer(&to),
            unsigned.clone(),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        let json = serde_json::to_value(&unsigned).unwrap();
        let parsed: UnsignedTx = serde_json::from_value(json).unwrap();
        assert!(matches!(parsed, UnsignedTx::Tron(_)));
        attach(
            &mut v,
            "tron",
            signer(&from),
            parsed,
            serde_json::json!({"ok":true}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "tron", "d", 4).unwrap();
        let rec = approve(&mut v, "tron", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        assert_eq!(
            rec.hash.as_deref(),
            Some(hex::encode(unsigned.txid().unwrap()).as_str())
        );
        report(&mut v, "tron", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "tron", TxState::Pending, None, "d", 7).unwrap();
        assert_eq!(
            report(&mut v, "tron", TxState::Expired, None, "d", 8)
                .unwrap()
                .state,
            TxState::Expired
        );
        load_ledger(&v).unwrap().validate().unwrap();
        let mut mainnet = intent("tron-main", &to, "1");
        mainnet.chain_id = ChainId("tron:0x2b6653dc".into());
        assert!(propose(&mut v, mainnet, "d", 9).is_err());
    }

    /// Propose, attach, sign and expire one native transfer for a family the core signs
    /// through the plain `sign(secret)` path; the mainnet intent must be refused.
    #[allow(clippy::too_many_arguments)]
    fn family_transfer_flow(
        id: &str,
        chain: &str,
        mainnet: &str,
        curve: Curve,
        paths: [&str; 2],
        address: fn(&[u8]) -> Result<String>,
        amount: &str,
        make: impl Fn(String, String) -> UnsignedTx,
    ) {
        let mut v = vault();
        let public = |path: &str| {
            hex::decode(provenance::public_key(&v, "w", curve, path).unwrap()).unwrap()
        };
        let from = address(&public(paths[0])).unwrap();
        let to = address(&public(paths[1])).unwrap();
        let unsigned = make(from.clone(), to.clone());
        let mut i = intent(id, &to, amount);
        i.chain_id = ChainId(chain.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{chain}:native")),
            amount: Amount(amount.into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: paths[0].into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(&unsigned).unwrap()).unwrap();
        assert_eq!(
            std::mem::discriminant(&parsed),
            std::mem::discriminant(&unsigned)
        );
        assert!(attach(
            &mut v,
            id,
            signer(&to),
            parsed.clone(),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            id,
            signer(&from),
            parsed,
            serde_json::json!({"ok":true}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, id, "d", 4).unwrap();
        let rec = approve(&mut v, id, &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        assert!(rec.raw_signed_hex.is_some() && rec.hash.is_some());
        report(&mut v, id, TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, id, TxState::Pending, None, "d", 7).unwrap();
        assert_eq!(
            report(&mut v, id, TxState::Expired, None, "d", 8)
                .unwrap()
                .state,
            TxState::Expired
        );
        load_ledger(&v).unwrap().validate().unwrap();
        let mut main = intent(&format!("{id}-main"), &to, "1");
        main.chain_id = ChainId(mainnet.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn substrate_westend_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "dot",
            substrate::WESTEND,
            "polkadot:91b171bb158e2d3848fa23a9f1c25182",
            Curve::Ed25519,
            ["m/44'/354'/0'/0'/0'", "m/44'/354'/0'/0'/1'"],
            substrate::address,
            "1500000000000",
            |from, to| {
                UnsignedTx::Substrate(SubstrateTx {
                    chain_id: substrate::WESTEND.into(),
                    from,
                    to,
                    planck: "1500000000000".into(),
                    tip: "0".into(),
                    nonce: 5,
                    spec_version: 1_025_002,
                    transaction_version: 27,
                    genesis_hash:
                        "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e".into(),
                    block_hash: format!("0x{}", "ab".repeat(32)),
                    block_number: 1_000_000,
                    era_period: 256,
                    metadata_hash_mode: 0,
                })
            },
        );
    }

    #[test]
    fn stellar_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "xlm",
            stellar::TESTNET,
            "stellar:pubnet",
            Curve::Ed25519,
            ["m/44'/148'/0'", "m/44'/148'/1'"],
            stellar::address,
            "15000000",
            |from, to| {
                UnsignedTx::Stellar(StellarTx {
                    chain_id: stellar::TESTNET.into(),
                    from,
                    to,
                    stroops: "15000000".into(),
                    fee: 1000,
                    seq_num: "12000340488487103".into(),
                    max_time: 1_760_001_800,
                    built_at: 1_760_000_000,
                    create_account: false,
                })
            },
        );
    }

    #[test]
    fn aptos_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "apt",
            aptos::TESTNET,
            "aptos:1",
            Curve::Ed25519,
            ["m/44'/637'/0'/0'/0'", "m/44'/637'/0'/0'/1'"],
            aptos::address,
            "150000000",
            |from, to| {
                UnsignedTx::Aptos(AptosTx {
                    chain_id: aptos::TESTNET.into(),
                    from,
                    to,
                    octas: "150000000".into(),
                    sequence_number: "3".into(),
                    max_gas_amount: 2_000,
                    gas_unit_price: 100,
                    expiration_timestamp_secs: 1_800,
                })
            },
        );
    }

    #[test]
    fn xrpl_testnet_payment_signs_as_the_derived_address() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let path = "m/44'/144'/0'/0/0";
        let public = provenance::signing_key(&vault(), "w", Curve::Secp256k1, path)
            .unwrap()
            .public;
        let compressed = k256::PublicKey::from_sec1_bytes(&public)
            .unwrap()
            .to_encoded_point(true);
        let public_key_hex = hex::encode(compressed.as_bytes());
        family_transfer_flow(
            "xrp",
            xrpl::TESTNET,
            xrpl::MAINNET,
            Curve::Secp256k1,
            [path, "m/44'/144'/0'/0/1"],
            xrpl::address,
            "1500000",
            |from, to| {
                UnsignedTx::Xrpl(XrplTx {
                    chain_id: xrpl::TESTNET.into(),
                    from,
                    to,
                    drops: "1500000".into(),
                    fee: 12,
                    sequence: 7,
                    last_ledger_sequence: 1_300,
                    built_at_ledger: 1_000,
                    destination_tag: Some(42),
                    public_key_hex: public_key_hex.clone(),
                })
            },
        );
    }

    #[test]
    fn sui_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "sui",
            sui::TESTNET,
            "sui:mainnet",
            Curve::Ed25519,
            ["m/44'/784'/0'/0'/0'", "m/44'/784'/0'/0'/1'"],
            sui::address,
            "1500000000",
            |from, to| {
                UnsignedTx::Sui(SuiTx {
                    chain_id: sui::TESTNET.into(),
                    from,
                    to,
                    mist: "1500000000".into(),
                    gas_payment: vec![sui::SuiObjectRef {
                        object_id: format!("0x{}", "11".repeat(32)),
                        version: 42,
                        digest: bs58::encode([7u8; 32]).into_string(),
                    }],
                    gas_price: 1_000,
                    gas_budget: 5_000_000,
                })
            },
        );
    }

    #[test]
    fn near_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "near",
            near::TESTNET,
            near::MAINNET,
            Curve::Ed25519,
            ["m/44'/397'/0'", "m/44'/397'/1'"],
            near::address,
            "1500000000000000000000000",
            |from, to| {
                UnsignedTx::Near(NearTx {
                    chain_id: near::TESTNET.into(),
                    from,
                    to,
                    yocto: "1500000000000000000000000".into(),
                    nonce: "7".into(),
                    block_hash: bs58::encode([9u8; 32]).into_string(),
                    block_height: 190_000_000,
                })
            },
        );
    }

    #[test]
    fn algorand_testnet_payment_signs_as_the_derived_address() {
        family_transfer_flow(
            "algo",
            algorand::TESTNET,
            algorand::MAINNET,
            Curve::Ed25519,
            ["m/44'/283'/0'/0'/0'", "m/44'/283'/1'/0'/0'"],
            algorand::address,
            "1500000",
            |from, to| {
                UnsignedTx::Algorand(AlgorandTx {
                    chain_id: algorand::TESTNET.into(),
                    from,
                    to,
                    microalgos: "1500000".into(),
                    fee: 1_000,
                    first_valid: 50_000_000,
                    last_valid: 50_001_000,
                    genesis_id: algorand::TESTNET_GENESIS_ID.into(),
                    genesis_hash: algorand::TESTNET_GENESIS_HASH.into(),
                })
            },
        );
    }

    #[test]
    fn ton_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "ton",
            ton::TESTNET,
            ton::MAINNET,
            Curve::Ed25519,
            ["m/44'/607'/0'", "m/44'/607'/1'"],
            ton::address,
            "10000000",
            |from, to| {
                UnsignedTx::Ton(TonTx {
                    chain_id: ton::TESTNET.into(),
                    from,
                    to,
                    nanoton: "10000000".into(),
                    seqno: 0,
                    valid_until: 1_800,
                    built_at: 1,
                    bounce: false,
                    deploy: true,
                })
            },
        );
    }

    #[test]
    fn cardano_preprod_transfer_signs_from_the_cip1852_account() {
        family_transfer_flow(
            "ada",
            cardano::PREPROD,
            cardano::MAINNET,
            Curve::Ed25519,
            ["m/1852'/1815'/0'/0/0", "m/1852'/1815'/1'/0/0"],
            cardano::address,
            "2000000",
            |from, to| {
                UnsignedTx::Cardano(CardanoTx {
                    chain_id: cardano::PREPROD.into(),
                    from,
                    to,
                    lovelace: "2000000".into(),
                    inputs: vec![cardano::CardanoInput {
                        tx_hash: "ab".repeat(32),
                        index: 0,
                        lovelace: "10000000".into(),
                    }],
                    fee: 200_000,
                    ttl: 1_000,
                    built_slot: 100,
                    min_fee_a: 44,
                    min_fee_b: 155_381,
                    coins_per_utxo_byte: 4_310,
                })
            },
        );
    }

    #[test]
    fn antelope_wax_testnet_transfer_binds_the_signing_key() {
        let mut v = vault();
        let path = "m/44'/194'/0'/0/0";
        let public =
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, path).unwrap()).unwrap();
        let key = antelope::address(&public).unwrap();
        let other = hex::decode(
            provenance::public_key(&v, "w", Curve::Secp256k1, "m/44'/194'/0'/0/1").unwrap(),
        )
        .unwrap();
        let other_key = antelope::address(&other).unwrap();
        let to = "swt1d1faf1fv";
        let mut i = intent("wax", to, "125000000");
        i.chain_id = ChainId(antelope::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.into(),
            asset: AssetRef(format!("{}:native", antelope::TESTNET)),
            amount: Amount("125000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |public_key: &str| {
            UnsignedTx::Antelope(AntelopeTx {
                chain_id: antelope::TESTNET.into(),
                from: "swth2cwye1ww".into(),
                permission: "active".into(),
                to: to.into(),
                antelope_units: "125000000".into(),
                symbol: "WAX".into(),
                precision: 8,
                token_contract: "eosio.token".into(),
                memo: String::new(),
                expiration: 1_700_001_800,
                ref_block_num: 1,
                ref_block_prefix: 2,
                built_at_secs: 1_700_000_000,
                public_key: public_key.into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&key)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Antelope(_)));
        assert!(attach(
            &mut v,
            "wax",
            signer(&key),
            tx(&other_key),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "wax",
            signer(&key),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "wax", "d", 4).unwrap();
        let rec = approve(&mut v, "wax", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        assert!(rec.raw_signed_hex.unwrap().contains("SIG_K1_"));
        report(&mut v, "wax", TxState::Broadcast, None, "d", 6).unwrap();
        assert_eq!(
            report(&mut v, "wax", TxState::Expired, None, "d", 7)
                .unwrap()
                .state,
            TxState::Expired
        );
        let mut main = intent("wax-main", to, "1");
        main.chain_id = ChainId(antelope::WAX_MAINNET.into());
        assert!(propose(&mut v, main, "d", 8).is_err());
    }
    #[test]
    fn multiversx_devnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "egld",
            multiversx::DEVNET,
            "mvx:1",
            Curve::Ed25519,
            ["m/44'/508'/0'/0'/0'", "m/44'/508'/0'/0'/1'"],
            multiversx::address,
            "1500000000000000000",
            |from, to| {
                UnsignedTx::Multiversx(MultiversxTx {
                    chain_id: multiversx::DEVNET.into(),
                    from,
                    to,
                    attoegld: "1500000000000000000".into(),
                    nonce: 0,
                    gas_price: 1_000_000_000,
                    gas_limit: 50_000,
                })
            },
        );
    }
    #[test]
    fn tezos_shadownet_transfer_reveals_and_signs_as_the_derived_address() {
        family_transfer_flow(
            "xtz",
            tezos::SHADOWNET,
            tezos::MAINNET,
            Curve::Ed25519,
            ["m/44'/1729'/0'/0'", "m/44'/1729'/1'/0'"],
            tezos::address,
            "1000000",
            |from, to| {
                UnsignedTx::Tezos(TezosTx {
                    chain_id: tezos::SHADOWNET.into(),
                    from,
                    to,
                    mutez: "1000000".into(),
                    branch: "BLockGenesisGenesisGenesisGenesisGenesisf79b5d1CoW2".into(),
                    counter: 7,
                    fee: 550,
                    gas_limit: 2_201,
                    storage_limit: 257,
                    reveal: Some(tezos::TezosReveal {
                        fee: 128,
                        gas_limit: 271,
                    }),
                })
            },
        );
    }
    #[test]
    fn stacks_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "stx",
            stacks::TESTNET,
            "stacks:1",
            Curve::Secp256k1,
            ["m/44'/5757'/0'/0/0", "m/44'/5757'/0'/0/1"],
            stacks::address,
            "1000000",
            |from, to| {
                UnsignedTx::Stacks(StacksTx {
                    chain_id: stacks::TESTNET.into(),
                    from,
                    to,
                    microstx: "1000000".into(),
                    fee: 200,
                    nonce: 0,
                })
            },
        );
    }
    #[test]
    fn vechain_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "vet",
            vechain::TESTNET,
            vechain::MAINNET,
            Curve::Secp256k1,
            ["m/44'/818'/0'/0/0", "m/44'/818'/0'/0/1"],
            vechain::address,
            "1000000000000000000",
            |from, to| {
                UnsignedTx::Vechain(VechainTx {
                    chain_id: vechain::TESTNET.into(),
                    from,
                    to,
                    vet_wei: "1000000000000000000".into(),
                    block_ref: "000000000a0b0c0d".into(),
                    expiration: 180,
                    gas_price_coef: 0,
                    gas: 21_000,
                    nonce: "0123456789abcdef".into(),
                })
            },
        );
    }
    #[test]
    fn hyperliquid_testnet_transfer_signs_as_the_derived_address() {
        family_transfer_flow(
            "hype",
            hyperliquid::TESTNET,
            "hype:mainnet",
            Curve::Secp256k1,
            ["m/44'/60'/0'/0/0", "m/44'/60'/0'/0/1"],
            hyperliquid::address,
            "1500000",
            |from, to| {
                UnsignedTx::Hyperliquid(HyperliquidTx {
                    chain_id: hyperliquid::TESTNET.into(),
                    from,
                    to,
                    hl_usd_micro: "1500000".into(),
                    time: 1_760_000_000_000,
                    built_at_ms: 1_760_000_000_000,
                })
            },
        );
    }
    #[test]
    fn gala_testnet_transfer_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/60'/0'/0/0";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap()
        };
        let from = gala::address(&public_of(path)).unwrap();
        let to = gala::address(&public_of("m/44'/60'/0'/0/1")).unwrap();
        let mut i = intent("gala", &to, "150000000");
        i.chain_id = ChainId(gala::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", gala::TESTNET)),
            amount: Amount("150000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Gala(GalaTx {
                chain_id: gala::TESTNET.into(),
                from: from.into(),
                to: to.clone(),
                gunits: "150000000".into(),
                unique_key: "testkey1".into(),
                dto_expires_at: 1_800_000_000_000,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Gala(_)));
        assert!(attach(
            &mut v,
            "gala",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "gala",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "gala", "d", 4).unwrap();
        let rec = approve(&mut v, "gala", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "gala", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "gala", TxState::Pending, None, "d", 7).unwrap();
        // dtoExpiresAt is a real on-chain expiry.
        report(&mut v, "gala", TxState::Expired, None, "d", 8).unwrap();
        let mut main = intent("gala-main", &to, "1");
        main.chain_id = ChainId(gala::MAINNET.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn mixin_kernel_transfer_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/2365'/0'/0'/0'";
        let secret_of = |p: &str| {
            *provenance::signing_key(&v, "w", Curve::Ed25519, p)
                .unwrap()
                .secret()
        };
        let from_pub = mixin::public_from_secret(&secret_of(path));
        let from = mixin::address(&from_pub).unwrap();
        let to = mixin::address(&mixin::public_from_secret(&secret_of(
            "m/44'/2365'/0'/0'/1'",
        )))
        .unwrap();
        let mut i = intent("xin", &to, "150000000");
        i.chain_id = ChainId(mixin::MAINNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", mixin::MAINNET)),
            amount: Amount("150000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let (key, mask) = mixin::ghost_public_for_test(&[0x42u8; 64], &from_pub, 0);
        let tx = |from: &str| {
            UnsignedTx::Mixin(MixinTx {
                chain_id: mixin::MAINNET.into(),
                from: from.into(),
                to: to.clone(),
                xinat: "150000000".into(),
                inputs: vec![crate::mixin::MixinInput {
                    hash: "11".repeat(32),
                    index: 0,
                    key: hex::encode(key),
                    mask: hex::encode(mask),
                    xinat: "200000000".into(),
                }],
                to_seed: "ab".repeat(64),
                change_seed: "cd".repeat(64),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Mixin(_)));
        assert!(attach(
            &mut v,
            "xin",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "xin",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "xin", "d", 4).unwrap();
        let rec = approve(&mut v, "xin", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "xin", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "xin", TxState::Pending, None, "d", 7).unwrap();
        // Kernel transactions never expire; reporting Expired must be refused.
        assert!(report(&mut v, "xin", TxState::Expired, None, "d", 8).is_err());
    }

    #[test]
    fn qubic_transfer_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/83293'/0'/0'/0'";
        let secret_of = |p: &str| {
            *provenance::signing_key(&v, "w", Curve::Ed25519, p)
                .unwrap()
                .secret()
        };
        let identity_of =
            |p: &str| qubic::address(&qubic::public_key(&secret_of(p)).unwrap()).unwrap();
        let from = identity_of(path);
        let to = identity_of("m/44'/83293'/0'/0'/1'");
        let mut i = intent("qu", &to, "25");
        i.chain_id = ChainId(qubic::QUBIC_MAINNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", qubic::QUBIC_MAINNET)),
            amount: Amount("25".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Qubic(QubicTx {
                chain_id: qubic::QUBIC_MAINNET.into(),
                from: from.into(),
                to: to.clone(),
                qu: "25".into(),
                tick: 1_000_000,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Qubic(_)));
        assert!(attach(
            &mut v,
            "qu",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "qu",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "qu", "d", 4).unwrap();
        let rec = approve(&mut v, "qu", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "qu", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "qu", TxState::Pending, None, "d", 7).unwrap();
        // The target tick is a real on-chain expiry.
        report(&mut v, "qu", TxState::Expired, None, "d", 8).unwrap();
    }

    #[test]
    fn btcfork_dash_transfer_signs_as_the_derived_address() {
        use sha2::Digest;
        let mut v = vault();
        let path = "m/44'/1'/0'/0/0";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap()
        };
        let from_pub = public_of(path);
        let from = btcfork::address(btcfork::DASH_TESTNET, &from_pub).unwrap();
        let to = btcfork::address(btcfork::DASH_TESTNET, &public_of("m/44'/1'/0'/0/1")).unwrap();
        let main_pub = public_of("m/44'/5'/0'/0/0");
        let mut i = intent("tdash", &to, "50000");
        i.chain_id = ChainId(btcfork::DASH_TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", btcfork::DASH_TESTNET)),
            amount: Amount("50000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        // A synthetic funding tx paying 100_000 sats to the sender; its txid is
        // the reversed sha256d of its bytes, which sign() re-verifies.
        let funding_for = |pubkey: &[u8]| {
            let h160 = hex::encode(ripemd::Ripemd160::digest(sha2::Sha256::digest(pubkey)));
            let funding = format!(
                "0300000001{}0100000003515151ffffffff02a0860100000000001976a914{}88ac01000000000000001976a914{}88ac00000000",
                "02".repeat(32),
                h160,
                h160
            );
            let fb = hex::decode(&funding).unwrap();
            let mut txid_bytes = sha2::Sha256::digest(sha2::Sha256::digest(&fb)).to_vec();
            txid_bytes.reverse();
            (funding, hex::encode(txid_bytes))
        };
        let tx_funded_by = |from: &str, pubkey: &[u8]| {
            let (funding, txid) = funding_for(pubkey);
            UnsignedTx::BtcFork(BtcForkTx {
                chain_id: btcfork::DASH_TESTNET.into(),
                from: from.into(),
                to: to.clone(),
                satoshis: "50000".into(),
                fee: "500".into(),
                inputs: vec![crate::btcfork::BtcForkInput {
                    txid,
                    vout: 0,
                    previous_tx_hex: funding,
                }],
                expiry_height: None,
                consensus_branch_id: None,
            })
        };
        let tx = |from: &str| tx_funded_by(from, &from_pub);
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::BtcFork(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "tdash",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        // A mainnet-coin-type key (SLIP-44 5) holds real DASH at the same
        // script, so it must never sign a "testnet" fork transaction.
        let main_from = btcfork::address(btcfork::DASH_TESTNET, &main_pub).unwrap();
        let err = attach(
            &mut v,
            "tdash",
            Signer {
                wallet_id: "w".into(),
                path: "m/44'/5'/0'/0/0".into(),
                address: main_from.clone(),
            },
            tx_funded_by(&main_from, &main_pub),
            serde_json::json!({}),
            true,
            "d",
            2,
        )
        .unwrap_err();
        assert!(err.to_string().contains("coin type 1"), "{err}");
        attach(
            &mut v,
            "tdash",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "tdash", "d", 4).unwrap();
        let rec = approve(&mut v, "tdash", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "tdash", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "tdash", TxState::Pending, None, "d", 7).unwrap();
        // Zcash/Verus v4 transactions expire by height, so the family reports
        // Expired for real (the spent-input case also lands here).
        report(&mut v, "tdash", TxState::Expired, None, "d", 8).unwrap();
        // Mainnet entries are read-only; signing stays testnet-gated.
        let mut main = intent("bch-main", &to, "1");
        main.chain_id = ChainId("btcfork:bch-mainnet".into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn namada_housefire_transfer_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/877'/0'/0'/0'";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Ed25519, p).unwrap()).unwrap()
        };
        let from = namada::address(&public_of(path)).unwrap();
        let to = namada::address(&public_of("m/44'/877'/0'/0'/1'")).unwrap();
        let nam = "tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7";
        let mut i = intent("nam", &to, "123456789");
        i.chain_id = ChainId("namada:cc0d3e0c033be".into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef("namada:cc0d3e0c033be:native".into()),
            amount: Amount("123456789".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Namada(NamadaTx {
                chain_id: "namada:cc0d3e0c033be".into(),
                from: from.into(),
                to: to.clone(),
                namnam: "123456789".into(),
                token: nam.into(),
                fee_token: nam.into(),
                fee_per_gas: "1".into(),
                gas_limit: 50_000,
                wasm_code_hash: "ab".repeat(32),
                timestamp: "2026-10-16T00:00:00.000000000+00:00".into(),
                code_salt: "0123456789abcdef".into(),
                data_salt: "0123456789abcdef".into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Namada(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "nam",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "nam",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "nam", "d", 4).unwrap();
        let rec = approve(&mut v, "nam", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "nam", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "nam", TxState::Pending, None, "d", 7).unwrap();
        // Wrapper txs carry no expiration; reporting Expired must be refused.
        assert!(report(&mut v, "nam", TxState::Expired, None, "d", 8).is_err());
        // Mainnet signing stays refused until a funded e2e flips the gate.
        let mut main = intent("nam-main", &to, "1");
        main.chain_id = ChainId("namada:5f5de2dd1b88cba30586420".into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn keeta_testnet_block_signs_as_the_derived_address() {
        let mut v = vault();
        let path = "m/44'/9797'/0'/0/0";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap()
        };
        let from = keeta::address(&public_of(path)).unwrap();
        let to = keeta::address(&public_of("m/44'/9797'/0'/0/1")).unwrap();
        let mut i = intent("kta", &to, "1000000000000000000");
        i.chain_id = ChainId(keeta::KEETA_TEST.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", keeta::KEETA_TEST)),
            amount: Amount("1000000000000000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Keeta(KeetaTx {
                chain_id: keeta::KEETA_TEST.into(),
                from: from.into(),
                to: to.clone(),
                atto_kta: "1000000000000000000".into(),
                previous: "ab".repeat(32),
                timestamp: 1_760_000_000,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Keeta(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "kta",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "kta",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "kta", "d", 4).unwrap();
        let rec = approve(&mut v, "kta", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "kta", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "kta", TxState::Pending, None, "d", 7).unwrap();
        // Keeta blocks never expire on-chain; reporting Expired must be refused.
        assert!(report(&mut v, "kta", TxState::Expired, None, "d", 8).is_err());
        // Mainnet signing stays refused (read-only there).
        let mut main = intent("kta-main", &to, "1");
        main.chain_id = ChainId("keeta:main".into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn chromia_testnet_transfer_and_register_sign() {
        let mut v = vault();
        let path = "m/44'/60'/0'/0/0";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap()
        };
        let from_pub = public_of(path);
        let to_pub = public_of("m/44'/60'/0'/0/1");
        let from = chromia::address(&from_pub).unwrap();
        let to = chromia::address(&to_pub).unwrap();
        let signer_hex = hex::encode(&from_pub);
        let mut i = intent("chr", &to, "1500000");
        i.chain_id = ChainId(chromia::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", chromia::TESTNET)),
            amount: Amount("1500000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Chromia(ChromiaTx {
                chain_id: chromia::TESTNET.into(),
                from: from.into(),
                signer: signer_hex.clone(),
                to: to.clone(),
                uchr: "1500000".into(),
                nonce: "ab".repeat(32),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Chromia(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "chr",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "chr",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "chr", "d", 4).unwrap();
        let rec = approve(&mut v, "chr", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "chr", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "chr", TxState::Pending, None, "d", 7).unwrap();
        // A GTX has no deadline; reporting Expired must be refused.
        assert!(report(&mut v, "chr", TxState::Expired, None, "d", 8).is_err());
        // The self-claim registration tx signs for the same account.
        let reg = UnsignedTx::ChromiaRegister(ChromiaRegisterTx {
            chain_id: chromia::TESTNET.into(),
            from: from.clone(),
            signer: signer_hex.clone(),
            register: true,
        });
        let mut ri = intent("chr-reg", &from, "0");
        ri.chain_id = ChainId(chromia::TESTNET.into());
        ri.kind = TxIntentKind::Transfer {
            to: from.clone(),
            asset: AssetRef(format!("{}:native", chromia::TESTNET)),
            amount: Amount("0".into()),
        };
        propose(&mut v, ri, "d", 9).unwrap();
        attach(
            &mut v,
            "chr-reg",
            signer(&from),
            reg,
            serde_json::json!({}),
            true,
            "d",
            10,
        )
        .unwrap();
        evaluate(&mut v, "chr-reg", "d", 11).unwrap();
        let rec = approve(&mut v, "chr-reg", &pw(), "d", 12).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        let mut main = intent("chr-main", &to, "1");
        main.chain_id = ChainId("chromia:0x15c0ca99bee60a3b".into());
        assert!(propose(&mut v, main, "d", 13).is_err());
    }

    #[test]
    fn obyte_testnet_unit_signs_as_the_derived_address() {
        use base64::Engine;
        let mut v = vault();
        let path = "m/44'/0'/0'/0/0";
        let public_of = |p: &str| {
            hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap()
        };
        let from = obyte::address(&public_of(path)).unwrap();
        let to = obyte::address(&public_of("m/44'/0'/0'/0/1")).unwrap();
        let author = base64::engine::general_purpose::STANDARD.encode(public_of(path));
        let mut i = intent("gbyte", &to, "1500000");
        i.chain_id = ChainId(obyte::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", obyte::TESTNET)),
            amount: Amount("1500000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let b64 = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
        let tx = |from: &str| {
            UnsignedTx::Obyte(ObyteTx {
                chain_id: obyte::TESTNET.into(),
                from: from.into(),
                author_pubkey: author.clone(),
                to: to.clone(),
                bytes: "1500000".into(),
                timestamp: 1_750_000_000,
                tps_fee: 0,
                parent_units: vec![b64(0x11)],
                last_ball: b64(0x22),
                last_ball_unit: b64(0x33),
                inputs: vec![crate::obyte::ObyteInput {
                    unit: b64(0x44),
                    message_index: 0,
                    output_index: 0,
                    amount: "2000000".into(),
                }],
                first_unit: false,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Obyte(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "gbyte",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "gbyte",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "gbyte", "d", 4).unwrap();
        let rec = approve(&mut v, "gbyte", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "gbyte", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "gbyte", TxState::Pending, None, "d", 7).unwrap();
        // Units never expire on-chain; reporting Expired must be refused.
        assert!(report(&mut v, "gbyte", TxState::Expired, None, "d", 8).is_err());
        let mut main = intent("gbyte-main", &to, "1");
        main.chain_id = ChainId("obyte:mainnet".into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn starcoin_barnard_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "stc",
            starcoin::BARNARD,
            "starcoin:1",
            Curve::Ed25519,
            ["m/44'/101010'/0'/0'/0'", "m/44'/101010'/0'/0'/1'"],
            starcoin::address,
            "123456789",
            |from, to| {
                UnsignedTx::Starcoin(StarcoinTx {
                    chain_id: starcoin::BARNARD.into(),
                    from,
                    to,
                    nano: "123456789".into(),
                    sequence_number: 41,
                    max_gas_amount: 10_000_000,
                    gas_unit_price: 1,
                    expiration_timestamp_secs: 1_750_000_000,
                })
            },
        );
    }

    #[test]
    fn aelf_tdvv_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "elf",
            aelf::TDVV,
            "aelf:AELF",
            Curve::Secp256k1,
            ["m/44'/1616'/0'/0/0", "m/44'/1616'/0'/0/1"],
            aelf::address,
            "150000000",
            |from, to| {
                UnsignedTx::Aelf(AelfTx {
                    chain_id: aelf::TDVV.into(),
                    from,
                    to,
                    elves: "150000000".into(),
                    ref_block_number: 20_000_000,
                    ref_block_prefix: "a1b2c3d4".into(),
                })
            },
        );
    }

    #[test]
    fn fuel_sepolia_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "fuel",
            fuel::SEPOLIA,
            fuel::MAINNET,
            Curve::Secp256k1,
            ["m/44'/1179993420'/0'/0/0", "m/44'/1179993420'/1'/0/0"],
            fuel::address,
            "123456789",
            |from, to| {
                UnsignedTx::Fuel(FuelTx {
                    chain_id: fuel::SEPOLIA.into(),
                    from,
                    to,
                    base: "123456789".into(),
                    inputs: vec![fuel::FuelCoinInput {
                        tx_id: format!("0x{}", "11".repeat(32)),
                        output_index: 0,
                        amount: "10000000000".into(),
                    }],
                    gas_limit: 0,
                    max_fee: "1000000".into(),
                    expiration: 7_600_000,
                })
            },
        );
    }

    #[test]
    fn chia_testnet11_spend_signs_the_standard_puzzle() {
        let mut v = vault();
        let path = "m/12381'/8444'/2'/0'";
        let address_of = |p: &str| {
            let public =
                hex::decode(provenance::public_key(&v, "w", Curve::Ed25519, p).unwrap()).unwrap();
            chia::address(&public).unwrap()
        };
        let from = address_of(path);
        let to = address_of("m/12381'/8444'/2'/1'");
        let mut i = intent("xch", &to, "1500000");
        i.chain_id = ChainId(chia::TESTNET11.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", chia::TESTNET11)),
            amount: Amount("1500000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Chia(ChiaTx {
                chain_id: chia::TESTNET11.into(),
                from: from.into(),
                to: to.clone(),
                mojos: "1500000".into(),
                fee: "100".into(),
                parent_coin_id: "ab".repeat(32),
                coin_mojos: "2000000".into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Chia(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "xch",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "xch",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "xch", "d", 4).unwrap();
        let rec = approve(&mut v, "xch", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "xch", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "xch", TxState::Pending, None, "d", 7).unwrap();
        // A Chia spend dies only when its coin is spent; Expired must be refused.
        assert!(report(&mut v, "xch", TxState::Expired, None, "d", 8).is_err());
        let mut main = intent("xch-main", &to, "1");
        main.chain_id = ChainId(chia::MAINNET.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn aeternity_testnet_transfer_flow() {
        family_transfer_flow(
            "aet",
            aeternity::TESTNET,
            "aet:ae_mainnet",
            Curve::Ed25519,
            ["m/44'/457'/0'/0'/0'", "m/44'/457'/0'/0'/1'"],
            aeternity::address,
            "1000000000000000",
            |from, to| {
                UnsignedTx::Aeternity(AeternityTx {
                    chain_id: aeternity::TESTNET.into(),
                    from,
                    to,
                    aettos: "1000000000000000".into(),
                    fee: "20000000000000".into(),
                    ttl: 1_400_000,
                    nonce: 1,
                })
            },
        );
    }

    #[test]
    fn alephium_testnet_transfer_signs_grouped_p2pkh() {
        let mut v = vault();
        let path = "m/44'/1234'/0'/0/0";
        let address_of = |p: &str| {
            let public =
                hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap();
            alephium::address(&public).unwrap()
        };
        let from = address_of(path);
        let to = address_of("m/44'/1234'/0'/0/1");
        let from_pub = provenance::public_key(&v, "w", Curve::Secp256k1, path).unwrap();
        let mut i = intent("alph", &to, "1000000000000000000");
        i.chain_id = ChainId(alephium::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", alephium::TESTNET)),
            amount: Amount("1000000000000000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Alephium(AlephiumTx {
                chain_id: alephium::TESTNET.into(),
                from: from.into(),
                public_key: from_pub.clone(),
                to: to.clone(),
                attoalph: "1000000000000000000".into(),
                change: "23998000000000000000".into(),
                inputs: vec![alephium::AlephiumInput {
                    hint: 1_088_969_728,
                    key: "ab".repeat(32),
                }],
                gas_amount: 20_000,
                gas_price: "100000000000".into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Alephium(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "alph",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "alph",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "alph", "d", 4).unwrap();
        let rec = approve(&mut v, "alph", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "alph", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "alph", TxState::Pending, None, "d", 7).unwrap();
        // Alephium transactions never expire; reporting Expired must be refused.
        assert!(report(&mut v, "alph", TxState::Expired, None, "d", 8).is_err());
        let mut main = intent("alph-main", &to, "1");
        main.chain_id = ChainId("alephium:0".into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn ergo_testnet_transfer_signs_p2pk_boxes() {
        let mut v = vault();
        let path = "m/44'/429'/0'/0/0";
        let address_of = |p: &str| {
            let public =
                hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap();
            ergo::address(&public).unwrap()
        };
        let from = address_of(path);
        let to = address_of("m/44'/429'/0'/0/1");
        let mut i = intent("erg", &to, "1000000000");
        i.chain_id = ChainId(ergo::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", ergo::TESTNET)),
            amount: Amount("1000000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Ergo(ErgoTx {
                chain_id: ergo::TESTNET.into(),
                from: from.into(),
                to: to.clone(),
                nanoerg: "1000000000".into(),
                inputs: vec!["ab".repeat(32)],
                change: "10000000".into(),
                fee: "1000000".into(),
                height: 598_000,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Ergo(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "erg",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "erg",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "erg", "d", 4).unwrap();
        let rec = approve(&mut v, "erg", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "erg", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "erg", TxState::Pending, None, "d", 7).unwrap();
        // Ergo transactions never expire; reporting Expired must be refused.
        assert!(report(&mut v, "erg", TxState::Expired, None, "d", 8).is_err());
        let mut main = intent("erg-main", &to, "1");
        main.chain_id = ChainId(ergo::MAINNET.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn icp_mainnet_transfer_signs_with_strict_bounds() {
        let mut v = vault();
        let path = "m/44'/223'/0'/0/0";
        let address_of = |p: &str| {
            let public =
                hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap();
            icp::address(&public).unwrap()
        };
        let from = address_of(path);
        let to = address_of("m/44'/223'/0'/0/1");
        let mut i = intent("icp", &to, "100000000");
        i.chain_id = ChainId(icp::MAINNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", icp::MAINNET)),
            amount: Amount("100000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Icp(IcpTx {
                chain_id: icp::MAINNET.into(),
                from: from.into(),
                to: to.clone(),
                e8s: "100000000".into(),
                memo: 0,
                created_at_nanos: "1760000000000000000".into(),
                ingress_expiry_nanos: "1760000240000000000".into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Icp(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "icp",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "icp",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "icp", "d", 4).unwrap();
        let rec = approve(&mut v, "icp", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "icp", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "icp", TxState::Pending, None, "d", 7).unwrap();
        // Past the ingress expiry the replica drops the request.
        assert_eq!(
            report(&mut v, "icp", TxState::Expired, None, "d", 8)
                .unwrap()
                .state,
            TxState::Expired
        );
        // Any other chain id must be refused.
        let mut other = intent("icp-other", &to, "1");
        other.chain_id = ChainId("icp:00000000000000000001".into());
        assert!(propose(&mut v, other, "d", 9).is_err());
    }

    #[test]
    fn radix_stokenet_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "xrd",
            radix::STOKENET,
            radix::MAINNET,
            Curve::Ed25519,
            [
                "m/44'/1022'/2'/525'/1460'/0'",
                "m/44'/1022'/2'/525'/1460'/1'",
            ],
            radix::address,
            "1000000000000000000",
            |from, to| {
                UnsignedTx::Radix(RadixTx {
                    chain_id: radix::STOKENET.into(),
                    from,
                    to,
                    attos: "1000000000000000000".into(),
                    start_epoch_inclusive: 100,
                    end_epoch_exclusive: 110,
                    nonce: 7,
                    tip_percentage: 0,
                })
            },
        );
    }

    #[test]
    fn waves_testnet_transfer_binds_the_axolotl_signing_key() {
        let mut v = vault();
        let path = "m/44'/5741564'/0'/0'/0'";
        let public_of = |p: &str| provenance::public_key(&v, "w", Curve::Ed25519, p).unwrap();
        let address_of = |p: &str| waves::address(&hex::decode(public_of(p)).unwrap()).unwrap();
        let from = address_of(path);
        let from_pub = public_of(path);
        let to = address_of("m/44'/5741564'/0'/0'/1'");
        let mut i = intent("waves", &to, "100000000");
        i.chain_id = ChainId(waves::TESTNET.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", waves::TESTNET)),
            amount: Amount("100000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Waves(WavesTx {
                chain_id: waves::TESTNET.into(),
                from: from.into(),
                to: to.clone(),
                wavelets: "100000000".into(),
                public_key_hex: from_pub.clone(),
                timestamp: 1_760_000_000_000,
                built_at_ms: 1_760_000_000_000,
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Waves(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "waves",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "waves",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "waves", "d", 4).unwrap();
        let rec = approve(&mut v, "waves", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        report(&mut v, "waves", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "waves", TxState::Pending, None, "d", 7).unwrap();
        assert_eq!(
            report(&mut v, "waves", TxState::Expired, None, "d", 8)
                .unwrap()
                .state,
            TxState::Expired
        );
        let mut main = intent("waves-main", &to, "1");
        main.chain_id = ChainId(waves::MAINNET.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn everscale_venom_testnet_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "venom",
            everscale::TESTNET,
            everscale::VENOM_MAINNET,
            Curve::Ed25519,
            ["m/44'/1'/0'/0'/0'", "m/44'/1'/0'/0'/1'"],
            everscale::address,
            "1000000000",
            |from, to| {
                UnsignedTx::Everscale(EverscaleTx {
                    chain_id: everscale::TESTNET.into(),
                    from,
                    to,
                    evers: "1000000000".into(),
                    time_ms: 1_760_000_000_000,
                    expire_at: 1_760_001_800,
                    built_at_ms: 1_760_000_000_000,
                    bounce: false,
                    deploy: false,
                })
            },
        );
    }

    #[test]
    fn icon_lisbon_transfer_flows_through_the_ledger() {
        family_transfer_flow(
            "icx",
            icon::LISBON,
            icon::MAINNET,
            Curve::Secp256k1,
            ["m/44'/4801368'/0'/0'/0'", "m/44'/4801368'/0'/0'/1'"],
            icon::address,
            "1000000000000000000",
            |from, to| {
                UnsignedTx::Icon(IconTx {
                    chain_id: icon::LISBON.into(),
                    from,
                    to,
                    r#loop: "1000000000000000000".into(),
                    nonce: 1,
                    step_limit: 100_000,
                    timestamp: 1_760_000_000_000_000,
                    built_at_ms: 1_760_000_000_000,
                })
            },
        );
    }

    #[test]
    fn starknet_sepolia_transfer_deploys_and_signs_as_the_derived_account() {
        let mut v = vault();
        let path = "m/44'/9004'/0'/0/0";
        let address_of = |p: &str| {
            let public =
                hex::decode(provenance::public_key(&v, "w", Curve::Secp256k1, p).unwrap()).unwrap();
            starknet::address(&public).unwrap()
        };
        let from = address_of(path);
        let to = address_of("m/44'/9004'/0'/0/1");
        let mut i = intent("strk", &to, "1000000000000000000");
        i.chain_id = ChainId(starknet::SEPOLIA.into());
        i.kind = TxIntentKind::Transfer {
            to: to.clone(),
            asset: AssetRef(format!("{}:native", starknet::SEPOLIA)),
            amount: Amount("1000000000000000000".into()),
        };
        propose(&mut v, i, "d", 1).unwrap();
        let tx = |from: &str| {
            UnsignedTx::Starknet(StarknetTx {
                chain_id: starknet::SEPOLIA.into(),
                from: from.into(),
                to: to.clone(),
                fri: "1000000000000000000".into(),
                nonce: 1,
                deploy: true,
                tip: "0".into(),
                l1_gas_max_amount: 0,
                l1_gas_max_price: "0".into(),
                l2_gas_max_amount: 4_000_000,
                l2_gas_max_price: "1000000000".into(),
                l1_data_gas_max_amount: 1_024,
                l1_data_gas_max_price: "1000000000".into(),
            })
        };
        let signer = |address: &str| Signer {
            wallet_id: "w".into(),
            path: path.into(),
            address: address.into(),
        };
        let parsed: UnsignedTx =
            serde_json::from_value(serde_json::to_value(tx(&from)).unwrap()).unwrap();
        assert!(matches!(parsed, UnsignedTx::Starknet(_)));
        // Signing as the recipient account must be refused.
        assert!(attach(
            &mut v,
            "strk",
            signer(&to),
            tx(&to),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        attach(
            &mut v,
            "strk",
            signer(&from),
            parsed,
            serde_json::json!({}),
            true,
            "d",
            3,
        )
        .unwrap();
        evaluate(&mut v, "strk", "d", 4).unwrap();
        let rec = approve(&mut v, "strk", &pw(), "d", 5).unwrap();
        assert_eq!(rec.state, TxState::Signed);
        assert!(rec
            .raw_signed_hex
            .unwrap()
            .contains("deploy_account_transaction"));
        report(&mut v, "strk", TxState::Broadcast, None, "d", 6).unwrap();
        report(&mut v, "strk", TxState::Pending, None, "d", 7).unwrap();
        // v3 transactions have no expiry: reporting Expired must be refused.
        assert!(report(&mut v, "strk", TxState::Expired, None, "d", 8).is_err());
        let mut main = intent("strk-main", &to, "1");
        main.chain_id = ChainId(starknet::MAINNET.into());
        assert!(propose(&mut v, main, "d", 9).is_err());
    }

    #[test]
    fn cardano_refuses_a_non_cip1852_path() {
        assert_eq!(provenance::cardano_account("m/1852'/1815'/3'/0/0"), Some(3));
        for p in [
            "m/1852'/1815'/0'/2/0",
            "m/1852'/1815'/01'/0/0",
            "m/44'/1815'/0'/0/0",
            "m/1852'/1815'/2147483648'/0/0",
        ] {
            assert_eq!(provenance::cardano_account(p), None, "{p}");
        }
    }
    #[test]
    fn a_swapped_destination_or_signer_is_refused() {
        let mut v = vault();
        propose(&mut v, intent("t", TO, "1000"), "d", 1).unwrap();
        let evil = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
        assert!(attach(
            &mut v,
            "t",
            signer(),
            unsigned(evil, "1000"),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        let wrong = Signer {
            address: evil.into(),
            ..signer()
        };
        assert!(attach(
            &mut v,
            "t",
            wrong,
            unsigned(TO, "1000"),
            serde_json::json!({}),
            true,
            "d",
            2
        )
        .is_err());
        assert_eq!(load_ledger(&v).unwrap().txs[0].state, TxState::Draft);
    }

    #[test]
    fn swaps_must_match_the_intent_and_pay_the_signer() {
        let usdc = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
        let route = evm::swap_route("eip155:11155111").unwrap();
        let swap = |id: &str| {
            let mut i = intent(id, TO, "0");
            i.kind = TxIntentKind::Swap {
                sell: AssetRef("eip155:11155111:native".into()),
                sell_amount: Amount("1000".into()),
                buy: AssetRef(format!("eip155:11155111:erc20:{usdc}")),
                min_buy_amount: Amount("990".into()),
                max_slippage_bps: 100,
                aggregator: "uniswap-v3:3000".into(),
            };
            i
        };
        let tx = |recipient: &str, min: &str| EvmTx {
            gas_limit: 200_000,
            to: route.router.into(),
            value: "1000".into(),
            data_hex: hex::encode(
                evm::swap_calldata(route.weth, usdc, 3000, recipient, "1000", min).unwrap(),
            ),
            ..unsigned(TO, "0")
        };
        let attach_tx = |v: &mut EncryptedVault, id: &str, t: EvmTx| {
            attach(v, id, signer(), t, serde_json::json!({}), true, "d", 2)
        };
        let mut v = vault();
        propose(&mut v, swap("ok"), "d", 1).unwrap();
        assert!(attach_tx(&mut v, "ok", tx(ADDR, "990")).is_ok());

        propose(&mut v, swap("pay-other"), "d", 1).unwrap();
        let err = attach_tx(&mut v, "pay-other", tx(TO, "990")).unwrap_err();
        assert!(err.to_string().contains("signing account"), "{err}");

        propose(&mut v, swap("no-floor"), "d", 1).unwrap();
        assert!(attach_tx(&mut v, "no-floor", tx(ADDR, "1")).is_err());

        let mut other_router = tx(ADDR, "990");
        other_router.to = TO.into();
        propose(&mut v, swap("router"), "d", 1).unwrap();
        assert!(attach_tx(&mut v, "router", other_router).is_err());
    }

    #[test]
    fn policies_deny_and_recheck_at_signing_time() {
        let mut v = vault();
        set_policies(
            &mut v,
            vec![Policy {
                id: "p".into(),
                name: "deny".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::DestinationDeny {
                    addresses: vec![TO.into()],
                }],
            }],
            "d",
            0,
        )
        .unwrap();
        let t = to_awaiting(&mut v, "t1");
        assert_eq!(t.state, TxState::Denied);

        set_policies(&mut v, vec![], "d", 0).unwrap();
        let t = to_awaiting(&mut v, "t2");
        assert_eq!(t.state, TxState::Awaiting);
        set_policies(
            &mut v,
            vec![Policy {
                id: "cap".into(),
                name: "cap".into(),
                mode: PolicyMode::Enforce,
                rules: vec![Rule::SpendCap {
                    window: Window::Tx,
                    usd_micros: 1,
                }],
            }],
            "d",
            9,
        )
        .unwrap();
        let t = approve(&mut v, "t2", &pw(), "d", 10).unwrap();
        assert_eq!(t.state, TxState::Rejected);
        assert!(t.raw_signed_hex.is_none());
    }

    #[test]
    fn the_log_cannot_be_rewritten() {
        let mut v = vault();
        to_awaiting(&mut v, "t1");
        let mut l = load_ledger(&v).unwrap();
        l.txs[0].state = TxState::Signed;
        assert!(save_ledger(&mut v, &l).is_err(), "state without a log row");
        let mut l = load_ledger(&v).unwrap();
        l.audit.pop();
        l.txs[0].state = TxState::Evaluated;
        assert!(save_ledger(&mut v, &l).is_err(), "dropped row");
        reject(&mut v, "t1", "d", 9).unwrap();
        assert_eq!(load_ledger(&v).unwrap().txs[0].state, TxState::Rejected);
    }
}
