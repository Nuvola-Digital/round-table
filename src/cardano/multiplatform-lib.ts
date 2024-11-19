import type { ProtocolParams, TransactionOutput } from '@cardano-graphql/client-ts/api'
import { type Address, type Bip32PrivateKey, type Certificate, type Ed25519KeyHash, type NativeScript, RewardAddress, type SingleInputBuilder, type SingleOutputBuilderResult, type Transaction, type TransactionBuilder, type TransactionHash, type Value as CMLValue, type Vkeywitness, type PrivateKey, type Bip32PublicKey, type Credential, type SingleWithdrawalBuilder, type BigInteger, TransactionMetadatum, Rational } from '@dcspark/cardano-multiplatform-lib-browser'
import { useEffect, useState } from 'react'
import { db } from '../db'
import type { PersonalAccount, PersonalWallet, MultisigAccount, Policy, KeyHashIndex } from '../db'
import { isMainnet } from './config'
import type { Config } from './config'
import type { Value } from './react-query-api'
import { getAssetName, getPolicyId } from './react-query-api'
import { decryptWithPassword, harden } from './utils'

const COIN_TYPE = 1815
const PAYMENT_ROLE = 0
const STAKING_ROLE = 2
const PERSONAL_PURPOSE = 1852
const MULTISIG_PURPOSE = 1854

const PERSONAL_WALLET_PATH = [harden(PERSONAL_PURPOSE), harden(COIN_TYPE)]
const MULTISIG_WALLET_PATH = [harden(MULTISIG_PURPOSE), harden(COIN_TYPE)]

const personalStakingKeyHash = (publicKey: Bip32PublicKey): Ed25519KeyHash => publicKey.derive(STAKING_ROLE).derive(0).to_raw_key().hash()
const personalAccountPath = (accountIndex: number) => PERSONAL_WALLET_PATH.concat(harden(accountIndex))
const multisigAccountPath = (accountIndex: number) => MULTISIG_WALLET_PATH.concat(harden(accountIndex))

const Fraction = require('fractional').Fraction
type Fraction = { numerator: number, denominator: number }

type CardanoWASM = typeof import('@dcspark/cardano-multiplatform-lib-browser')
type Recipient = {
  address: string
  value: Value
}

const newRecipient = (): Recipient => {
  return {
    address: '',
    value: {
      lovelace: BigInt(0),
      assets: new Map()
    }
  }
}

const isAddressNetworkCorrect = (config: Config, address: Address): boolean => {
  const networkId = address.network_id()
  return isMainnet(config) ? networkId === 1 : networkId === 0
}

const toAddressString = (address: Address): string => address.to_bech32()

type Result<T> =
  | { isOk: true, data: T }
  | { isOk: false, message: string }

function getResult<T>(callback: () => T): Result<T> {
  try {
    return {
      isOk: true,
      data: callback()
    }
  } catch (error) {
    return {
      isOk: false,
      message: error instanceof Error ? error.message : String(error)
    }
  }
}

interface CardanoIterable<T> {
  len: () => number
  get: (index: number) => T
}

function toIter<T>(set: CardanoIterable<T>): IterableIterator<T> {
  let index = 0
  return {
    next: () => {
      return index < set.len() ? {
        done: false,
        value: set.get(index++)
      } : { done: true, value: null }
    },
    [Symbol.iterator]: function () { return this }
  }
}

interface ToBytes {
  to_bytes: () => Uint8Array
}

function encodeCardanoData(data: ToBytes | Uint8Array, encoding: BufferEncoding): string {
  const getBuffer = () => {
    if ('to_bytes' in data) {
      return Buffer.from(data.to_bytes())
    }
    return Buffer.from(data as Uint8Array)
  }
  return getBuffer().toString(encoding)
}

function toHex(data: ToBytes | Uint8Array): string {
  return encodeCardanoData(data, 'hex')
}

function verifySignature(txHash: TransactionHash, vkeywitness: Vkeywitness): boolean {
  const publicKey = vkeywitness.vkey()
  const signature = vkeywitness.ed25519_signature()
  return publicKey.verify(txHash.to_raw_bytes(), signature)
}

class Cardano {
  private _wasm: CardanoWASM

  public constructor(wasm: CardanoWASM) {
    this._wasm = wasm
  }

  public get lib() {
    return this._wasm
  }

  public buildTxOutput(recipient: Recipient, protocolParams: ProtocolParams): SingleOutputBuilderResult {
    if (recipient.value.lovelace < this.getMinLovelace(recipient, protocolParams)) {
      const error = new Error('Insufficient ADA')
      error.name = 'InsufficientADAError'
      throw error
    }
    const { TransactionOutputBuilder } = this.lib
    return TransactionOutputBuilder
      .new()
      .with_address(this.parseAddress(recipient.address))
      .next()
      .with_value(this.buildCMLValue(recipient.value))
      .build()
  }

  public getMinLovelace(recipient: Recipient, protocolParams: ProtocolParams): bigint {
    const { BigInteger, TransactionOutput } = this.lib
    if (!protocolParams.coinsPerUtxoByte) throw new Error('coinsPerUtxoByte is missing')
    const coinsPerUtxoByte = BigInteger.from_str(protocolParams.coinsPerUtxoByte.toString())
    const address = this.parseAddress(recipient.address)
    const txOutput = TransactionOutput.new(address, this.buildCMLValue(recipient.value))
    const minimum = this.lib.min_ada_required(
      txOutput,
      coinsPerUtxoByte.as_u64() ?? BigInt(0)
    )
    return minimum
  }

  public buildCMLValue(value: Value): CMLValue {
    const { AssetName, BigInteger, MultiAsset, ScriptHash } = this.lib
    const { lovelace, assets } = value
    const multiAsset = MultiAsset.new()
    if (assets.size > 0) {
      assets.forEach((quantity, id, _) => {
        const policyId = ScriptHash.from_raw_bytes(Buffer.from(getPolicyId(id), 'hex'))
        const assetName = AssetName.from_raw_bytes(Buffer.from(getAssetName(id), 'hex'))
        const value = quantity
        multiAsset.set(policyId, assetName, value)
      })
    }
    return this.lib.Value.new(lovelace, multiAsset)
  }

  public createTxInputBuilder(input: TransactionOutput): SingleInputBuilder {
    const { AssetName, MultiAsset, ScriptHash, SingleInputBuilder, TransactionHash, TransactionInput, } = this.lib
    const hash = TransactionHash.from_hex(input.txHash)
    const index = BigInt(input.index)
    const txInput = TransactionInput.new(hash, index)
    const multiAsset = MultiAsset.new()
    if (input.tokens.length > 0) {
      input.tokens.forEach((token) => {
        const assetId = token.asset.assetId
        const policyId = ScriptHash.from_raw_bytes(Buffer.from(getPolicyId(assetId), 'hex'))
        const assetName = AssetName.from_raw_bytes(Buffer.from(getAssetName(assetId), 'hex'))
        const quantity = BigInt(token.quantity)
        multiAsset.set(policyId, assetName, quantity)
      })
    }
    const value = this.lib.Value.new(BigInt(input.value), multiAsset)

    const txOuput = this.lib.TransactionOutput.new(this.parseAddress(input.address), value)
    return SingleInputBuilder.new(txInput, txOuput)
  }

  public getMessageLabel(): BigInteger {
    return this.lib.BigInteger.from_str('674')
  }

  public getTxMessage(transaction: Transaction): string[] | undefined {
    const label = this.getMessageLabel()
    const metadatum = transaction.auxiliary_data()?.metadata()?.get(label.as_u64() ?? BigInt(0))?.as_map()?.get(TransactionMetadatum.new_text('msg'))?.as_list()
    return metadatum && (Array.from(toIter(metadatum), (metadata) => metadata.as_text()) as string[])
  }

  public signTransaction(transaction: Transaction, vkeys: Vkeywitness[]): Transaction {
    const { Transaction, VkeywitnessList } = this.lib
    const witnessSet = transaction.witness_set()
    const vkeyWitnessSet = VkeywitnessList.new()
    vkeys.forEach((vkey) => vkeyWitnessSet.add(vkey))
    witnessSet.set_vkeywitnesses(vkeyWitnessSet)
    return Transaction.new(transaction.body(), witnessSet, true, transaction.auxiliary_data())
  }

  public buildSignatureSetHex(vkeys: Array<Vkeywitness> | Vkeywitness | undefined): string | undefined {
    if (!vkeys) return
    const { TransactionWitnessSetBuilder } = this.lib
    const builder = TransactionWitnessSetBuilder.new()
    if (Array.isArray(vkeys)) {
      vkeys.forEach((vkey) => builder.add_vkey(vkey))
    } else {
      builder.add_vkey(vkeys)
    }
    return toHex(builder.build().to_cbor_bytes())
  }

  public parseAddress(address: string): Address {
    const { Address } = this.lib
    if (Address.is_valid_bech32(address)) return Address.from_bech32(address)
    const error = new Error('The address is invalid.')
    error.name = 'InvalidAddressError'
    throw error
  }

  public isValidAddress(address: string): boolean {
    const { Address } = this.lib
    return Address.is_valid(address)
  }

  public createTxBuilder(protocolParameters: ProtocolParams): TransactionBuilder {
    const { ExUnitPrices, UnitInterval, TransactionBuilder, TransactionBuilderConfigBuilder, LinearFee } = this.lib
    const { minFeeA, minFeeB, poolDeposit, keyDeposit,
      coinsPerUtxoByte, maxTxSize, maxValSize, maxCollateralInputs,
      priceMem, priceStep, collateralPercent } = protocolParameters

    if (!coinsPerUtxoByte) throw new Error('coinsPerUtxoByte is missing')
    if (!maxValSize) throw new Error('maxValSize is missing')
    if (!priceMem) throw new Error('priceMem is missing')
    if (!priceStep) throw new Error('priceStep is missing')
    if (!collateralPercent) throw new Error('collateralPercent is missing')
    if (!maxCollateralInputs) throw new Error('maxCollateralInputs is missing')

    const priceMemFraction: Fraction = new Fraction(priceMem)
    const priceStepFraction: Fraction = new Fraction(priceStep)
    const exUnitPrices = ExUnitPrices.new(
      Rational.new(BigInt(priceMemFraction.numerator), BigInt(priceMemFraction.denominator)),
      Rational.new(BigInt(priceStepFraction.numerator), BigInt(priceStepFraction.denominator))
    )
    const config = TransactionBuilderConfigBuilder.new()
      .fee_algo(LinearFee.new(BigInt(minFeeA), BigInt(minFeeB), BigInt(0))) // TODO: Ref script fee from protocol params
      .pool_deposit(BigInt(poolDeposit))
      .key_deposit(BigInt(keyDeposit))
      .coins_per_utxo_byte(BigInt(coinsPerUtxoByte))
      .max_tx_size(maxTxSize)
      .max_value_size(parseFloat(maxValSize))
      .ex_unit_prices(exUnitPrices)
      .collateral_percentage(collateralPercent)
      .max_collateral_inputs(maxCollateralInputs)
      .build()
    return TransactionBuilder.new(config)
  }

  public getNativeScriptFromPolicy(policy: Policy, getKeyHash: (address: Address) => Ed25519KeyHash): NativeScript {
    const { Address, NativeScript, NativeScriptList,  ScriptAll, ScriptAny, ScriptNOfK, ScriptPubkey } = this.lib
    if (typeof policy === 'string') {
      const keyHash = getKeyHash(Address.from_bech32(policy))
      return NativeScript.new_script_pubkey(ScriptPubkey.new(keyHash).ed25519_key_hash())
    }
    switch (policy.type) {
      case 'TimelockStart': return NativeScript.new_script_invalid_hereafter(BigInt(policy.slot))
      case 'TimelockExpiry': return NativeScript.new_script_invalid_before(BigInt(policy.slot))
    }
    const nativeScripts = NativeScriptList.new()
    policy.policies.forEach((policy) => {
      nativeScripts.add(this.getNativeScriptFromPolicy(policy, getKeyHash))
    })
    switch (policy.type) {
      case 'All': return NativeScript.new_script_all(nativeScripts)
      case 'Any': return NativeScript.new_script_any(nativeScripts)
      case 'NofK': return NativeScript.new_script_n_of_k(BigInt(policy.number), nativeScripts)
    }
  }

  public getPaymentNativeScriptFromPolicy(policy: Policy): NativeScript {
    return this.getNativeScriptFromPolicy(policy, (address) => {
      const keyHash = address.payment_cred()?.as_pub_key()
      if (!keyHash) throw new Error('No key hash of payment')
      return keyHash
    })
  }

  public getStakingNativeScriptFromPolicy(policy: Policy): NativeScript {
    return this.getNativeScriptFromPolicy(policy, (address) => {
      const keyHash = address.staking_cred()?.as_pub_key()
      if (!keyHash) throw new Error('No key hash of staking')
      return keyHash
    })
  }

  public getPolicyAddress(policy: Policy, isMainnet: boolean): Address {
    const { Address, BaseAddress, Credential } = this.lib
    if (typeof policy === 'string') return Address.from_bech32(policy)
    const paymentScript = this.getPaymentNativeScriptFromPolicy(policy)
    const stakingScript = this.getStakingNativeScriptFromPolicy(policy)
    const networkId = this.getNetworkId(isMainnet)
    const payment = Credential.new_script(paymentScript.hash())
    const staking = Credential.new_script(stakingScript.hash())
    return BaseAddress.new(networkId, payment, staking).to_address()
  }

  public getPolicyRewardAddress(policy: Policy, isMainnet: boolean): RewardAddress {
    const { RewardAddress, Credential } = this.lib
    const networkId = this.getNetworkId(isMainnet)
    if (typeof policy === 'string') {
      const credential = this.parseAddress(policy).staking_cred()
      if (!credential) throw new Error('Staking credential is missing')
      return RewardAddress.new(networkId, credential)
    }
    const script = this.getStakingNativeScriptFromPolicy(policy)
    return RewardAddress.new(networkId, Credential.new_script(script.hash()))
  }

  public getRequiredSignatures(script: NativeScript): number {
    const { NativeScriptKind } = this.lib
    const totalNumber = script.get_required_signers().len()
    switch (script.kind()) {
      case NativeScriptKind.ScriptAll: return totalNumber
      case NativeScriptKind.ScriptAny: return 1
      case NativeScriptKind.ScriptNOfK:
        const nofK = script.as_script_n_of_k()
        if (!nofK) throw new Error('cannot convert to ScriptNofK')
        return Number(nofK.n())
      default: throw new Error(`Unsupported Script Type: ${script.kind()}`)
    }
  }

  public createRegistrationCertificate(rewardAddress: string): Certificate | undefined {
    const { Address, Certificate, StakeRegistration } = this.lib
    const credential = Address.from_bech32(rewardAddress).staking_cred()
    if (!credential) return
    return Certificate.new_stake_registration(credential)
  }

  public createDeregistrationCertificate(rewardAddress: string): Certificate | undefined {
    const { Address, Certificate, StakeDeregistration } = this.lib
    const credential = Address.from_bech32(rewardAddress).staking_cred()
    if (!credential) return
    return Certificate.new_stake_deregistration(credential)
  }

  public createDelegationCertificate(rewardAddress: string, poolId: string): Certificate | undefined {
    const { Address, Certificate, StakeDelegation, Ed25519KeyHash } = this.lib
    const credential = Address.from_bech32(rewardAddress).staking_cred()
    const poolKeyHash = Ed25519KeyHash.from_bech32(poolId)
    if (!credential) return
    return Certificate.new_stake_delegation(credential, poolKeyHash)
  }

  public createWithdrawalBuilder(rewardAddress: string, amount: bigint): SingleWithdrawalBuilder | undefined {
    const { Address, SingleWithdrawalBuilder } = this.lib
    const address = RewardAddress.from_address(Address.from_bech32(rewardAddress))
    if (!address) return
    return SingleWithdrawalBuilder.new(address, amount)
  }

  public getNetworkId(isMainnet: boolean): number {
    const { NetworkInfo } = this.lib
    const networkInfo = isMainnet ? NetworkInfo.mainnet() : NetworkInfo.testnet()
    return networkInfo.network_id()
  }

  public readRewardAddressFromPublicKey(bytes: Uint8Array, isMainnet: boolean): RewardAddress {
    const { RewardAddress, Bip32PublicKey, Credential } = this.lib
    const networkId = this.getNetworkId(isMainnet)
    const publicKey = Bip32PublicKey.from_raw_bytes(bytes)
    const credential = Credential.new_pub_key(personalStakingKeyHash(publicKey))
    return RewardAddress.new(networkId, credential)
  }

  public sign(signingKey: PrivateKey, txHash: Uint8Array): Vkeywitness {
    const { PublicKey, Vkeywitness } = this.lib
    const signature = signingKey.sign(txHash)
    const verifyingKey = signingKey.to_public()
    return Vkeywitness.new(verifyingKey, signature)
  }

  public async getRootKey(wallet: PersonalWallet, password: string): Promise<Bip32PrivateKey> {
    return decryptWithPassword(wallet.rootKey, password, wallet.id)
      .then((plaintext) => this.lib.Bip32PrivateKey.from_raw_bytes(new Uint8Array(plaintext)))
  }

  public async signWithPersonalWallet(requiredKeyHashHexes: string[], txHash: Uint8Array, wallet: PersonalWallet, password: string): Promise<Vkeywitness[]> {
    const rootKey = await this.getRootKey(wallet, password)
    const collection: Vkeywitness[] = []
    const requiredKeyHashes: Uint8Array[] = requiredKeyHashHexes.map((hex) => Buffer.from(hex, 'hex'))

    const keyHashIndices = await db.keyHashIndices.where('hash').anyOf(requiredKeyHashes).and(({ walletId }) => walletId === wallet.id).toArray()

    keyHashIndices.forEach(({ hash, derivationPath }) => {
      const signingKey = derivationPath.reduce((key, index) => key.derive(index), rootKey).to_raw_key()
      const publicKeyHash = signingKey.to_public().hash()
      if (publicKeyHash.to_hex() !== toHex(hash)) {
        console.error('Publich key hashes do not match')
        return
      }
      collection.push(this.sign(signingKey, txHash))
    })

    return collection
  }

  public async generatePersonalAccount(wallet: PersonalWallet, password: string, accountIndex: number): Promise<KeyHashIndex[]> {
    const rootKey = await this.getRootKey(wallet, password)
    const accountPath = personalAccountPath(accountIndex)
    const publicKey = accountPath.reduce((key, index) => key.derive(index), rootKey).to_public().to_raw_bytes()
    wallet.personalAccounts.set(accountIndex, { publicKey, paymentKeyHashes: [] })
    return Array.from({ length: 6 }, () => this.generatePersonalAddress(wallet, accountIndex)).flat()
  }

  public async generateMultisigAccount(wallet: PersonalWallet, password: string, accountIndex: number): Promise<KeyHashIndex[]> {
    const rootKey = await this.getRootKey(wallet, password)
    const accountPath = multisigAccountPath(accountIndex)
    const publicKey = accountPath.reduce((key, index) => key.derive(index), rootKey).to_public().to_raw_bytes()
    wallet.multisigAccounts.set(accountIndex, { publicKey, addresses: [] })
    return Array.from({ length: 6 }, () => this.generateMultisigAddress(wallet, accountIndex)).flat()
  }

  public generatePersonalAddress(wallet: PersonalWallet, accountIndex: number): KeyHashIndex[] {
    const account = wallet.personalAccounts.get(accountIndex)
    if (!account) throw new Error('No account found with this index')
    const { Bip32PublicKey } = this.lib
    const publicKey = Bip32PublicKey.from_raw_bytes(account.publicKey)
    const index = account.paymentKeyHashes.length
    const paymentKeyHash = publicKey.derive(PAYMENT_ROLE).derive(index).to_raw_key().hash()
    const stakingKeyHash = personalStakingKeyHash(publicKey)
    account.paymentKeyHashes.push(paymentKeyHash.to_raw_bytes())

    const accountPath = personalAccountPath(accountIndex)
    const paymentPath = accountPath.concat([PAYMENT_ROLE, index])
    const stakingPath = accountPath.concat([STAKING_ROLE, 0])
    return [
      { hash: paymentKeyHash.to_raw_bytes(), derivationPath: paymentPath, walletId: wallet.id },
      { hash: stakingKeyHash.to_raw_bytes(), derivationPath: stakingPath, walletId: wallet.id }
    ]
  }

  public generateMultisigAddress(wallet: PersonalWallet, accountIndex: number): KeyHashIndex[] {
    const account = wallet.multisigAccounts.get(accountIndex)
    if (!account) throw new Error('No account found with this index')
    const { Bip32PublicKey } = this.lib
    const publicKey = Bip32PublicKey.from_raw_bytes(account.publicKey)
    const index = account.addresses.length
    const paymentKeyHash = publicKey.derive(PAYMENT_ROLE).derive(index).to_raw_key().hash()
    const stakingKeyHash = publicKey.derive(STAKING_ROLE).derive(index).to_raw_key().hash()
    account.addresses.push({
      paymentKeyHash: paymentKeyHash.to_raw_bytes(),
      stakingKeyHash: stakingKeyHash.to_raw_bytes()
    })

    const accountPath = multisigAccountPath(accountIndex)
    const paymentPath = accountPath.concat([PAYMENT_ROLE, index])
    const stakingPath = accountPath.concat([STAKING_ROLE, index])
    return [
      { hash: paymentKeyHash.to_raw_bytes(), derivationPath: paymentPath, walletId: wallet.id },
      { hash: stakingKeyHash.to_raw_bytes(), derivationPath: stakingPath, walletId: wallet.id }
    ]
  }

  public readStakeCredentialFromKeyHash(bytes: Uint8Array): Credential {
    const { Ed25519KeyHash, Credential } = this.lib
    return Credential.new_pub_key(Ed25519KeyHash.from_raw_bytes(bytes))
  }

  public getAddressesFromPersonalAccount(account: PersonalAccount, isMainnet: boolean): string[] {
    const { BaseAddress, Bip32PublicKey, Credential } = this.lib
    const publicKey = Bip32PublicKey.from_raw_bytes(account.publicKey)
    const stakingKeyHash = personalStakingKeyHash(publicKey)
    const staking = Credential.new_pub_key(stakingKeyHash)
    return account.paymentKeyHashes.map((paymentKeyHash) => {
      const payment = this.readStakeCredentialFromKeyHash(paymentKeyHash)
      const address = BaseAddress.new(this.getNetworkId(isMainnet), payment, staking).to_address().to_bech32()
      return address
    })
  }

  public getAddressesFromMultisigAccount(account: MultisigAccount, isMainnet: boolean): string[] {
    const { BaseAddress } = this.lib
    return account.addresses.map(({ paymentKeyHash, stakingKeyHash }) => {
      const payment = this.readStakeCredentialFromKeyHash(paymentKeyHash)
      const staking = this.readStakeCredentialFromKeyHash(stakingKeyHash)
      const address = BaseAddress.new(this.getNetworkId(isMainnet), payment, staking).to_address().to_bech32()
      return address
    })
  }
}

class Factory {
  private _instance?: Cardano

  public get instance() {
    return this._instance
  }

  public async load() {
    if (!this.instance)
      this._instance = new Cardano(await import('@dcspark/cardano-multiplatform-lib-browser'))
    return this.instance
  }
}

const Loader = new Factory()

const useCardanoMultiplatformLib = () => {
  const [cardano, setCardano] = useState<Cardano | undefined>(undefined)

  useEffect(() => {
    Loader.load().then((instance) => {
      setCardano(instance)
    })
  }, [])

  return cardano
}

export type { Cardano, CardanoIterable, Result, Recipient }
export { encodeCardanoData, getResult, toIter, toHex, useCardanoMultiplatformLib, verifySignature, Loader, newRecipient, isAddressNetworkCorrect, toAddressString }
