import { useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { MouseEventHandler, FC, ReactNode, ChangeEventHandler } from 'react'
import { AssetAmount, ADAAmount, LabeledCurrencyInput, getADASymbol, ADAInput } from './currency'
import { collectTransactionOutputs, decodeASCII, getAssetName, getBalanceByUTxOs, getPolicyId, useTransactionSummaryQuery, useStakePoolsQuery } from '../cardano/react-query-api'
import type { Value, RecipientRegistry } from '../cardano/react-query-api'
import { getResult, isAddressNetworkCorrect, newRecipient, toAddressString, toHex, toIter, useCardanoMultiplatformLib, verifySignature } from '../cardano/multiplatform-lib'
import type { Cardano, Recipient } from '../cardano/multiplatform-lib'
import { type Certificate, type TransactionHash, type TransactionInput, type Vkeywitness, type SingleInputBuilder, type InputBuilderResult, type SingleCertificateBuilder, type CertificateBuilderResult, type TransactionWitnessSet, type TransactionOutputList, type TransactionOutput as CMLTransactionOutput, type SingleWithdrawalBuilder, type WithdrawalBuilderResult, Metadata, Transaction } from '@dcspark/cardano-multiplatform-lib-browser'
import { ShareIcon, ArrowUpTrayIcon, PlusIcon, XMarkIcon, XCircleIcon, MagnifyingGlassIcon, ChevronLeftIcon, ChevronRightIcon, PencilIcon, WalletIcon, HeartIcon } from '@heroicons/react/24/solid'
import Link from 'next/link'
import { ConfigContext, donationAddress, isMainnet } from '../cardano/config'
import { CopyButton, Hero, Panel, ShareCurrentURLButton, Modal, TextareaModalBox } from './layout'
import { PasswordBox } from './password'
import { NotificationContext } from './notification'
import Image from 'next/image'
import Gun from 'gun'
import { getTransactionPath } from '../route'
import { Loading, SpinnerIcon } from './status'
import { NativeScriptViewer, SignatureViewer, TimelockExpiryViewer, TimelockStartViewer } from './native-script'
import type { VerifyingData } from './native-script'
import type { StakePool, TransactionOutput, ProtocolParams } from '@cardano-graphql/client-ts/api'
import init, { select } from 'cardano-utxo-wasm'
import type { Output } from 'cardano-utxo-wasm'
import { EditTimelockExpiry, EditTimelockStart, SlotInput } from './wallet'
import { useLiveQuery } from 'dexie-react-hooks'
import { db } from '../db'
import type { PersonalWallet } from '../db'
import { AddressableContent } from './address'
import { useLiveSlot } from './time'
import axios from 'axios'

const CertificateListing: FC<{
  cardano: Cardano
  certificate: Certificate
}> = ({ cardano, certificate }) => {
  const [config, _] = useContext(ConfigContext)
  const networkId: number = useMemo(() => cardano.getNetworkId(isMainnet(config)), [cardano, config])

  let cert

  cert = certificate.as_stake_registration()
  if (cert) {
    const { RewardAddress } = cardano.lib
    const rewardAddress = RewardAddress.new(networkId, cert.stake_credential()).to_address().to_bech32()
    return (
      <>
        <h2 className='font-semibold'>Stake Registration</h2>
        <AddressableContent content={rewardAddress} scanType='stakekey' />
      </>
    )
  }

  cert = certificate.as_stake_deregistration()
  if (cert) {
    const { RewardAddress } = cardano.lib
    const rewardAddress = RewardAddress.new(networkId, cert.stake_credential()).to_address().to_bech32()
    return (
      <>
        <h2 className='font-semibold'>Stake Deregistration</h2>
        <AddressableContent content={rewardAddress} scanType='stakekey' />
      </>
    )
  }

  cert = certificate.as_stake_delegation()
  if (cert) {
    const { RewardAddress } = cardano.lib
    const rewardAddress = RewardAddress.new(networkId, cert.stake_credential()).to_address().to_bech32()
    const poolId = cert.pool().to_bech32('pool')
    return (
      <>
        <h2 className='font-semibold'>Stake Delegation</h2>
        <AddressableContent content={rewardAddress} scanType='stakekey' />
        <AddressableContent content={poolId} scanType='pool' />
      </>
    )
  }

  throw new Error('Unsupported Certificate')
}

const CertificateList: FC<{
  cardano: Cardano
  ulClassName?: string
  liClassName?: string
  certificates: Certificate[]
}> = ({ cardano, ulClassName, liClassName, certificates }) => {
  return (
    <ul className={ulClassName}>
      {certificates.map((certificate, index) => <li className={liClassName} key={index}><CertificateListing cardano={cardano} certificate={certificate} /></li>)}
    </ul>
  )
}

const RecipientViewer: FC<{
  className?: string
  recipient: Recipient
}> = ({ className, recipient }) => {
  const { address, value } = recipient

  return (
    <div className={className}>
      <AddressableContent content={address} scanType='address' />
      <ul>
        <li><ADAAmount lovelace={value.lovelace} /></li>
        {Array.from(value.assets).map(([id, quantity]) =>
          <li key={id}>
            <AssetAmount
              quantity={quantity}
              decimals={0}
              symbol={decodeASCII(getAssetName(id))} />
          </li>
        )}
      </ul>
    </div>
  )
}

const getTxHash = (input: TransactionInput) => input.transaction_id().to_hex()
const getTxIndex = (input: TransactionInput) => Number(input.index())

const TransactionInputViewer: FC<{
  className?: string
  registry?: RecipientRegistry
  input: TransactionInput
}> = ({ className, input, registry }) => {
  const hash = getTxHash(input)
  const index = getTxIndex(input)
  const recipient = useMemo(() => registry?.get(hash)?.get(index), [hash, index, registry])

  if (recipient) return (
    <RecipientViewer className={className} recipient={recipient} />
  )

  return (
    <div className={className}>
      <div className='break-all'>{hash}#{index}</div>
    </div>
  )
}

type WalletAPI = {
  signTx(tx: string, partialSign: boolean): Promise<string>
  submitTx(tx: string): Promise<string>
  getNetworkId(): Promise<number>
}

type CIP30Wallet = {
  enable(): Promise<WalletAPI>
  name: string
  icon: string
  apiVersion: string
}

const getWalletIconURL = (wallet: CIP30Wallet): string => {
  switch (wallet.name) {
    case 'Typhon Wallet': return '/typhon.svg'
    default: return wallet.icon
  }
}

const CIP30WalletIcon: FC<{
  height?: number
  width?: number
  className?: string
  wallet: CIP30Wallet
}> = ({ height, width, wallet, className }) => {
  const iconURL = useMemo(() => getWalletIconURL(wallet), [wallet])

  return (
    <Image
      height={height || 25}
      width={width || 25}
      className={className}
      alt={wallet.name}
      src={iconURL}
    />
  )
}

type CIP30WalletName = 'eternl' | 'nami' | 'gero' | 'flint' | 'typhon'

const getCIP30Wallet = (name: CIP30WalletName): CIP30Wallet | undefined => {
  const cardano = (window as any).cardano
  switch (name) {
    case 'eternl': return cardano?.eternl
    case 'nami': return cardano?.nami
    case 'gero': return cardano?.gerowallet
    case 'flint': return cardano?.flint
    case 'typhon': return cardano?.typhoncip30
  }
}

type TxSignError = {
  code: 1 | 2
  info: string
}

const CIP30Names: CIP30WalletName[] = ['nami', 'gero', 'eternl', 'flint', 'typhon']
const SignTxButtonClassName = 'flex w-full items-center justify-between py-2 px-4 text-sky-700 disabled:bg-gray-100 disabled:text-gray-500 hover:bg-sky-100'
const SignTxButton: FC<{
  className?: string
  onSuccess: (signature: string) => void
  transaction: Transaction
  requiredKeyHashHexes: string[]
  children: ReactNode
}> = ({ className, onSuccess, transaction, requiredKeyHashHexes, children }) => {
  const cardano = useCardanoMultiplatformLib()
  const { notify } = useContext(NotificationContext)
  const txHash = useMemo(() => cardano?.lib.hash_transaction(transaction.body()).to_raw_bytes(), [cardano, transaction])
  const [modal, setModal] = useState(false)
  const closeModal = useCallback(() => setModal(false), [])
  const openModal = useCallback(() => setModal(true), [])
  const personalWallets = useLiveQuery(async () => db.personalWallets.toArray())
  const [signingWallet, setSigningWallet] = useState<PersonalWallet | 'import' | undefined>()
  useEffect(() => {
    if (!modal) setSigningWallet(undefined)
  }, [modal])
  const signWithPersonalWallet = useCallback(async (password: string) => {
    if (!signingWallet || signingWallet === 'import' || !cardano || !txHash) return
    cardano
      .signWithPersonalWallet(requiredKeyHashHexes, txHash, signingWallet, password)
      .then((vkeywitnesses) => {
        const { TransactionWitnessSetBuilder } = cardano.lib
        const builder = TransactionWitnessSetBuilder.new()
        vkeywitnesses.forEach((vkeywitness) => builder.add_vkey(vkeywitness))
        onSuccess(toHex(builder.build().to_canonical_cbor_bytes()))
        notify('success', 'Signed successfully')
      })
      .catch((error) => {
        notify('error', 'Failed to sign')
        console.error(error)
      })
      .finally(() => closeModal())
  }, [cardano, closeModal, onSuccess, requiredKeyHashHexes, signingWallet, txHash, notify])
  const isDisabled: boolean = useMemo(() => !signingWallet || !cardano || !txHash, [signingWallet, cardano, txHash])
  const [CIP30Wallets, setCIP30Wallets] = useState(new Map<CIP30WalletName, CIP30Wallet>())
  useEffect(() => {
    setCIP30Wallets(CIP30Names.reduce((result, name) => {
      const wallet = getCIP30Wallet(name)
      if (wallet) result.set(name, wallet)
      return result
    }, new Map()))
  }, [])
  const importSignature = useCallback((signature: string) => {
    onSuccess(signature)
    closeModal()
  }, [closeModal, onSuccess])
  useEffect(() => {
    if (personalWallets?.length === 0 && CIP30Wallets.size === 0 && modal) {
      setSigningWallet('import')
    }
  }, [personalWallets, CIP30Wallets, modal])

  return (
    <>
      <button onClick={openModal} className={className}>{children}</button>
      {modal && <Modal className='overflow-hidden w-80 text-center bg-white rounded divide-y' onBackgroundClick={closeModal}>
        {!signingWallet && <>
          <header>
            <h2 className='p-4 font-semibold bg-gray-100'>Choose a wallet</h2>
          </header>
          <nav className='text-sky-700 divide-y'>
            {personalWallets?.map((wallet) => <button
              key={wallet.id}
              onClick={() => setSigningWallet(wallet)}
              className={SignTxButtonClassName}>
              <WalletIcon className='w-6' />
              <span>{wallet.name}</span>
            </button>)}
            <button onClick={() => setSigningWallet('import')} className={SignTxButtonClassName}>
              <ArrowUpTrayIcon className='w-6' />
              <span>Import</span>
            </button>
            {Array.from(CIP30Wallets, ([name, wallet]) => <CIP30SignTxButton
              key={name}
              transaction={transaction}
              partialSign={true}
              sign={onSuccess}
              onFinish={closeModal}
              wallet={wallet}
              className={SignTxButtonClassName}>
              <CIP30WalletIcon wallet={wallet} className='w-4' />
              <span>{name.charAt(0).toUpperCase() + name.slice(1)}</span>
            </CIP30SignTxButton>)}
            <button onClick={closeModal} className='p-2 w-full text-center text-sky-700 hover:bg-sky-100'>Cancel</button>
          </nav>
        </>}
        {signingWallet && <>
          <header>
            <button
              onClick={() => setSigningWallet(undefined)}
              className='flex justify-center items-center p-2 space-x-1 w-full text-sky-700 hover:bg-sky-100'>
              <ChevronLeftIcon className='w-4' />
              <span>Choose Others</span>
            </button>
          </header>
          {signingWallet !== 'import' && <PasswordBox
            disabled={isDisabled}
            title={signingWallet.name}
            onConfirm={signWithPersonalWallet}>
            <PencilIcon className='w-4' />
            <span>Sign</span>
          </PasswordBox>}
          {signingWallet === 'import' && <TextareaModalBox placeholder='Input signature here and import' onConfirm={importSignature}>
            <ArrowUpTrayIcon className='w-4' />
            <span>Import</span>
          </TextareaModalBox>}
        </>}
      </Modal>}
    </>
  )
}

const CIP30SignTxButton: FC<{
  className?: string,
  children: ReactNode
  transaction: Transaction,
  partialSign: boolean,
  sign: (_: string) => void,
  onFinish?: () => void
  wallet: CIP30Wallet
}> = ({ wallet, transaction, partialSign, sign, className, children, onFinish }) => {

  const [config, _] = useContext(ConfigContext)
  const { notify } = useContext(NotificationContext)

  const onClick: MouseEventHandler<HTMLButtonElement> = useCallback(() => {
    wallet
      .enable()
      .then(async (walletAPI) => {
        const networkId = await walletAPI.getNetworkId()
        if (isMainnet(config) ? networkId !== 1 : networkId !== 0) {
          notify('error', 'Wrong network.')
          return
        }
        return walletAPI
          .signTx(toHex(transaction.to_canonical_cbor_bytes()), partialSign)
          .then(sign)
      })
      .catch((reason: Error | TxSignError) => {
        if ('info' in reason) {
          notify('error', reason.info)
          return
        }
        if ('message' in reason) {
          notify('error', reason.message)
          return
        }
        console.error(reason)
      })
      .finally(onFinish)
  }, [wallet, config, notify, onFinish, partialSign, sign, transaction])

  return (
    <button className={className} onClick={onClick}>
      {children}
    </button>
  )
}

const submitTx = (URL: string, cbor: string) => axios.post(URL,  {cbor})
.then((response) => {
  return response.data;
})
.catch(async (error) => {
  if (error.response && error.response.data) {
    const message: string = error.response.data.message;

    if (message.includes("(ScriptWitnessNotValidatingUTXOW")) {
      throw {
        name: 'InvalidSignatureError',
        message: 'The signatures are invalid.'
      }
    }
    if (message.includes("(BadInputsUTxO")) {
      throw {
        name: 'DuplicatedSpentError',
        message: 'The UTxOs have been spent.'
      }
    }
    console.error(message)
    throw {
      name: 'TxSubmissionError',
      message: 'An unknown error. Check the log.'
    };
  }

  // Handle network or unexpected errors
  console.error(error);
  throw {
    name: "NetworkError",
    message: "A network error occurred.",
  };
});

const SubmitTxButton: FC<{
  className?: string
  children: ReactNode
  transaction: Transaction
}> = ({ className, children, transaction }) => {
  const [config, _] = useContext(ConfigContext)
  const { notify } = useContext(NotificationContext)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isDisabled, setIsDisabled] = useState(false)

  const clickHandle: MouseEventHandler<HTMLButtonElement> = () => {
    setIsSubmitting(true)
    const promises = config.submitAPI.map((URL) => submitTx(URL, transaction.to_cbor_hex()))
    Promise
      .any(promises)
      .then(() => {
        notify('success', 'The transaction is submitted.')
      })
      .catch((reason: AggregateError) => {
        const duplicatedSpentError: Error = reason.errors.find((error) => error.name === 'DuplicatedSpentError')
        if (duplicatedSpentError) {
          setIsDisabled(true)
          notify('error', duplicatedSpentError.message)
          return
        }
        const invalidSignatureError: Error = reason.errors.find((error) => error.name === 'InvalidSignatureError')
        if (invalidSignatureError) {
          notify('error', invalidSignatureError.message)
          return
        }
        const error: Error = reason.errors[0]
        notify('error', error.message)
      })
      .finally(() => setIsSubmitting(false))
  }

  return (
    <button onClick={clickHandle} className={className} disabled={isDisabled || isSubmitting}>
      {isSubmitting ? 'Submitting' : children}
    </button>
  )
}

const WalletInfo: FC<{
  className?: string
  children: ReactNode
  name: CIP30WalletName
  src: string
}> = ({ name, className, children, src }) => {
  const [wallet, setWallet] = useState<CIP30Wallet | undefined>(undefined)

  useEffect(() => {
    setWallet(getCIP30Wallet(name))
  }, [name])

  return (
    <li className={className}>
      <div className='h-9'>
        <Image src={src} width={36} height={36} alt={name} />
      </div>
      <div>
        <div className='font-semibold'>{children}</div>
        <div className='text-sm text-gray-700'>{wallet?.apiVersion ?? 'Not Installed'}</div>
      </div>
    </li>
  )
}

const useAutoSync = (
  cardano: Cardano,
  txHash: TransactionHash,
  signatures: Map<string, Vkeywitness>,
  addSignatures: (witnessSetHex: string) => void,
  signers: Set<string>
) => {
  const [config, _] = useContext(ConfigContext)

  const gun = useMemo(() => {
    if (config.autoSync) return new Gun({ peers: config.gunPeers })
  }, [config.autoSync, config.gunPeers])

  useEffect(() => {
    if (!gun) return

    const nodes = Array.from(signers, (keyHashHex) => {
      const vkeywitness = signatures.get(keyHashHex)
      const node = gun
        .get('cardano')
        .get(config.network)
        .get('transactions')
        .get(toHex(txHash.to_raw_bytes()))
        .get(keyHashHex)

      if (vkeywitness) {
        const hex = cardano.buildSignatureSetHex([vkeywitness])
        node.put(hex)
        node.on((data) => {
          if (data !== hex) node.put(hex)
        })
      } else {
        node.on(addSignatures)
      }

      return node
    })

    return () => {
      nodes.forEach((node) => node.off())
    }
  }, [gun, addSignatures, cardano, config.network, signatures, signers, txHash])
}

const CopyVkeysButton: FC<{
  cardano: Cardano
  className?: string
  children: ReactNode
  vkeys: Vkeywitness[]
}> = ({ cardano, className, children, vkeys }) => {
  const hex = useMemo(() => cardano.buildSignatureSetHex(vkeys), [cardano, vkeys])

  return (
    <CopyButton
      content={hex}
      disabled={vkeys.length === 0}
      ms={500}
      className={className}>
      {children}
    </CopyButton>
  )
}

const TransactionLoader: FC<{
  content: Uint8Array
}> = ({ content }) => {
  const cardano = useCardanoMultiplatformLib()
  const transaction = useMemo(() => cardano?.lib.Transaction.from_cbor_bytes(content), [cardano, content])

  if (!cardano || !transaction) return (
    <Modal><Loading /></Modal>
  )

  return (
    <TransactionViewer cardano={cardano} transaction={transaction} />
  )
}

type SignatureMap = Map<string, Vkeywitness>

const updateSignatureMap = (witnessSet: TransactionWitnessSet, signatureMap: SignatureMap, txHash: TransactionHash): SignatureMap => {
  const result = new Map(signatureMap)
  const vkeyWitnessSet = witnessSet.vkeywitnesses()
  if (!vkeyWitnessSet) return result

  Array.from(toIter(vkeyWitnessSet), (vkeyWitness) => {
    const publicKey = vkeyWitness.vkey()
    const keyHashHex = publicKey.hash().to_hex()
    if (verifySignature(txHash, vkeyWitness)) {
      result.set(keyHashHex, vkeyWitness)
    }
  })

  return result
}

const getRecipientsFromCMLTransactionOutputs = (outputs: TransactionOutputList): Recipient[] => Array.from(toIter<CMLTransactionOutput>(outputs), (output: CMLTransactionOutput, index) => {
  const address = toAddressString(output.address())
  const amount = output.amount()
  const assets = new Map()
  const multiAsset = amount.multi_asset()
  if (multiAsset) {
    Array.from(toIter(multiAsset.keys()), (policyId) => {
      const _asset = multiAsset.get_assets(policyId)
      _asset && Array.from(toIter(_asset.keys()), (assetName) => {
        const quantity = BigInt(_asset.get(assetName) ?? 0)
        const id = policyId.to_hex() + toHex(assetName.to_raw_bytes())
        assets.set(id, (assets.get(id) ?? BigInt(0)) + quantity)
      })
    })
  }
  return {
    id: index.toString(),
    address,
    value: {
      lovelace: BigInt(amount.coin()),
      assets
    }
  }
})

const TransactionLifetime: FC<{
  startSlot?: number
  expirySlot?: number
}> = ({ startSlot, expirySlot }) => {
  console.log('expirySlot', expirySlot)
  const currentSlot = useLiveSlot()

  if (!startSlot && !expirySlot) return null

  return (
    <div className='space-y-1'>
      <h2 className='font-semibold'>Lifetime</h2>
      <div className='grid grid-cols-1 gap-2 lg:grid-cols-2'>
        <div className='p-2 text-sm rounded border'>
          {startSlot && <div className='flex justify-between items-center space-x-1'>
            <span>Start slot:</span>
            <TimelockStartViewer slot={startSlot} txStartSlot={currentSlot} />
          </div>}
          {expirySlot && <div className='flex justify-between items-center space-x-1'>
            <span>Expiry slot:</span>
            <TimelockExpiryViewer slot={expirySlot} txExpirySlot={currentSlot} />
          </div>}
        </div>
      </div>
    </div>
  )
}

const TransactionViewer: FC<{
  cardano: Cardano
  transaction: Transaction
}> = ({ cardano, transaction }) => {
  const nativeScripts = useMemo(() => {
    const scriptSet = transaction.witness_set().native_scripts()
    if (scriptSet) return Array.from(toIter(scriptSet))
  }, [transaction])
  const txBody = useMemo(() => transaction.body(), [transaction])
  const txHash = useMemo(() => cardano.lib.hash_transaction(txBody), [cardano, txBody])
  const txWithdrawals = useMemo(() => {
    const result = new Map<string, bigint>()
    const withdrawals = txBody.withdrawals()
    if (!withdrawals) return result
    Array.from(toIter(withdrawals.keys()), (address) => {
      const amount = withdrawals.get(address)
      if (amount) result.set(address.to_address().to_bech32(), BigInt(amount))
    })
    return result
  }, [txBody])
  const certificates = useMemo(() => {
    const certs = txBody.certs()
    if (!certs) return
    return Array.from(toIter(certs))
  }, [txBody])
  const requiredStakingKeys: Set<string> | undefined = useMemo(() => {
    if (!certificates && !txWithdrawals) return
    const collection = new Set<string>()

    certificates?.forEach((certificate) => {
      const cert = certificate.as_stake_registration() ??
        certificate.as_stake_delegation() ??
        certificate.as_stake_deregistration()
      const keyHashHex = cert?.stake_credential().to_cbor_hex()
      keyHashHex && collection.add(keyHashHex)
    })
    txWithdrawals.forEach((_, address) => {
      const keyHashHex = cardano.parseAddress(address).payment_cred()?.as_pub_key()?.to_hex()
      keyHashHex && collection.add(keyHashHex)
    })

    return collection
  }, [certificates, cardano, txWithdrawals])
  const [requiredPaymentKeys, setRequiredPaymentKeys] = useState<Set<string> | undefined>()
  const signerRegistry = useMemo(() => {
    const signers = new Set<string>()
    nativeScripts?.forEach((script) => {
      Array.from(toIter(script.get_required_signers()), (signer) => signers.add(toHex(signer.to_raw_bytes())))
    })
    requiredPaymentKeys?.forEach((keyHash) => signers.add(keyHash))
    requiredStakingKeys?.forEach((keyHash) => signers.add(keyHash))
    return signers
  }, [nativeScripts, requiredPaymentKeys, requiredStakingKeys])
  const [signatureMap, setSignatureMap] = useState<SignatureMap>(new Map())
  useEffect(() => setSignatureMap(updateSignatureMap(transaction.witness_set(), new Map(), txHash)), [transaction, txHash])
  const signedTransaction = useMemo(() => {
    const vkeys = new Array<Vkeywitness>()
    signatureMap.forEach((vkey, keyHashHex) => signerRegistry.has(keyHashHex) && vkeys.push(vkey))
    return cardano.signTransaction(transaction, vkeys)
  }, [cardano, transaction, signatureMap, signerRegistry])
  const txMessage = useMemo(() => cardano.getTxMessage(transaction), [cardano, transaction])
  const addSignatures = useCallback((witnessSetHex: string) => {
    const result = getResult(() => {
      const bytes = Buffer.from(witnessSetHex, 'hex')
      return cardano.lib.TransactionWitnessSet.from_cbor_bytes(bytes)
    })

    if (!result.isOk) return

    setSignatureMap(updateSignatureMap(result.data, signatureMap, txHash))
  }, [signatureMap, cardano, txHash])
  const fee = useMemo(() => txBody.fee(), [txBody])
  const txInputs = useMemo(() => Array.from(toIter(txBody.inputs())), [txBody])
  const { data } = useTransactionSummaryQuery({ hashes: txInputs.map((input) => input.transaction_id().to_hex()) })
  const txInputsRegistry = useMemo(() => data && collectTransactionOutputs(data.transactions), [data])
  const txRequiredSigners = useMemo(() => txBody.required_signers(), [txBody])
  useEffect(() => {
    const keyHashes = new Set<string>()
    txInputs.forEach((input) => {
      const hash = getTxHash(input)
      const index = getTxIndex(input)
      const address = txInputsRegistry?.get(hash)?.get(index)?.address
      const keyHash = address && cardano.parseAddress(address).payment_cred()?.as_pub_key()?.to_hex()
      keyHash && keyHashes.add(keyHash)
    })
    if (txRequiredSigners) {
      Array.from(toIter(txRequiredSigners))
        .map((signer) => toHex(signer.to_raw_bytes()))
        .forEach(keyHashes.add.bind(keyHashes));
    }
    setRequiredPaymentKeys(keyHashes)
  }, [cardano, txInputs, txInputsRegistry, txRequiredSigners, setRequiredPaymentKeys])
  const txOutputs: Recipient[] = useMemo(() => getRecipientsFromCMLTransactionOutputs(txBody.outputs()), [txBody])
  const startSlot = useMemo(() => {
    return txBody.validity_interval_start() ? Number(txBody.validity_interval_start()) : undefined
  }, [txBody])
  const expirySlot = useMemo(() => {
    return txBody.ttl() ? Number(txBody.ttl()) : undefined
  }, [txBody])
  const verifyingData: VerifyingData = useMemo(() => ({
    signatures: signatureMap,
    txStartSlot: startSlot,
    txExpirySlot: expirySlot
  }), [signatureMap, startSlot, expirySlot])
  useAutoSync(cardano, txHash, signatureMap, addSignatures, signerRegistry)

  return (
    <div className='space-y-2'>
      <Hero>
        <h1 className='text-lg font-semibold'>Review Transaction</h1>
        <p>If the transaction is correct, you can sign and submit it. If this transaction needs more than one signers, you can share them this URL to get it signed and share the signatures.</p>
        <nav>
          <ShareCurrentURLButton
            className='flex justify-center items-center px-2 py-1 space-x-1 w-32 text-sky-700 bg-white rounded shadow'>
            <ShareIcon className='w-4' />
            <span>Copy URL</span>
          </ShareCurrentURLButton>
        </nav>
      </Hero>
      <Panel>
        <div className='p-4 space-y-2'>
          <div className='space-y-1'>
            <h2 className='font-semibold'>Transaction ID</h2>
            <div className='text-sm'>
              <AddressableContent content={txHash.to_hex()} scanType='transaction' />
            </div>
          </div>
          <TransactionLifetime startSlot={startSlot} expirySlot={expirySlot} />
          <div className='grid grid-cols-1 gap-2 md:grid-cols-2'>
            <div className='space-y-1'>
              <div className='font-semibold'>Inputs</div>
              <ul className='space-y-1 text-sm'>
                {txInputs.map((input, index) => <li key={index} className='p-2 rounded border'>
                  <TransactionInputViewer className='space-y-1' input={input} registry={txInputsRegistry} />
                </li>)}
                {Array.from(txWithdrawals, ([address, amount], index) => <li key={index} className='p-2 space-y-1 rounded border'>
                  <AddressableContent content={address} scanType='stakekey' />
                  <div><ADAAmount lovelace={amount} /></div>
                </li>)}
              </ul>
            </div>
            <div className='space-y-1'>
              <div className='font-semibold'>Outputs</div>
              <ul className='space-y-1 text-sm'>
                {txOutputs.map((txOutput, index) => <li key={index} className='p-2 rounded border'>
                  <RecipientViewer className='space-y-1' recipient={txOutput} />
                </li>)}
                <li className='p-2 space-x-1 rounded border'>
                  <ADAAmount lovelace={fee} />
                  <span>Fee</span>
                </li>
              </ul>
            </div>
          </div>
          {certificates && <div className='space-y-1'>
            <div className='font-semibold'>Certificates</div>
            <CertificateList
              cardano={cardano}
              ulClassName='grid grid-cols-1 md:grid-cols-2 gap-2 text-sm'
              liClassName='p-2 border rounded break-all'
              certificates={certificates} />
          </div>}
          {txMessage && <div className='space-y-1'>
            <div className='font-semibold'>Message</div>
            <div className='p-2 text-sm break-all rounded border'>{txMessage.map((line, index) => <p key={index}>{line}</p>)}</div>
          </div>}
          {requiredPaymentKeys && requiredPaymentKeys.size > 0 && <div className='space-y-1'>
            <h2 className='font-semibold'>Required Payment Signatures</h2>
            <ul className='p-2 space-y-1 text-sm rounded border'>
              {Array.from(requiredPaymentKeys, (keyHashHex, index) => <li key={index}>
                <SignatureViewer
                  className='flex items-center space-x-1'
                  signedClassName='text-green-500'
                  name={keyHashHex}
                  signature={cardano.buildSignatureSetHex(signatureMap.get(keyHashHex))} />
              </li>)}
            </ul>
          </div>}
          {requiredStakingKeys && requiredStakingKeys.size > 0 && <div className='space-y-1'>
            <h2 className='font-semibold'>Required Staking Signatures</h2>
            <ul className='p-2 space-y-1 text-sm rounded border'>
              {Array.from(requiredStakingKeys, (keyHashHex, index) => <li key={index}>
                <SignatureViewer
                  className='flex items-center space-x-1'
                  signedClassName='text-green-500'
                  name={keyHashHex}
                  signature={cardano.buildSignatureSetHex(signatureMap.get(keyHashHex))} />
              </li>)}
            </ul>
          </div>}
          {nativeScripts && nativeScripts.length > 0 && <div className='space-y-1'>
            <h2 className='font-semibold'>Native Scripts</h2>
            <ul className='space-y-1 text-sm'>
              {nativeScripts.map((script, index) => <li key={index}>
                <NativeScriptViewer
                  cardano={cardano}
                  verifyingData={verifyingData}
                  className='p-2 space-y-2 rounded border'
                  headerClassName='font-semibold'
                  ulClassName='space-y-1'
                  nativeScript={script} />
              </li>)}
            </ul>
          </div>}
        </div>
        <footer className='flex justify-between items-center p-4 space-x-2 bg-gray-100'>
          <div className='flex space-x-2'>
            <SignTxButton
              transaction={transaction}
              requiredKeyHashHexes={Array.from(signerRegistry)}
              onSuccess={addSignatures}
              className='flex items-center p-2 space-x-1 text-white bg-sky-700 rounded disabled:border disabled:bg-gray-100 disabled:text-gray-400'>
              <PencilIcon className='w-4' />
              <span>Sign</span>
            </SignTxButton>
            <CopyVkeysButton
              cardano={cardano}
              vkeys={Array.from(signatureMap.values())}
              className='flex items-center p-2 space-x-1 text-white bg-sky-700 rounded disabled:border disabled:bg-gray-100 disabled:text-gray-400'>
              <ShareIcon className='w-4' />
              <span>Copy Signatures</span>
            </CopyVkeysButton>
          </div>
          <div className='flex space-x-2'>
            <SubmitTxButton
              className='flex items-center p-2 space-x-1 text-white bg-sky-700 rounded disabled:border disabled:bg-gray-100 disabled:text-gray-400'
              transaction={signedTransaction}>
              <ArrowUpTrayIcon className='w-4' />
              <span>Submit</span>
            </SubmitTxButton>
          </div>
        </footer>
      </Panel>
    </div>
  )
}

const AddAssetButton: FC<{
  budget: Value
  value: Value
  onSelect: (id: string) => void
}> = ({ budget, value, onSelect }) => {
  const assets = useMemo(() => Array
    .from(budget.assets)
    .filter(([id, quantity]) => !value.assets.has(id) && quantity > BigInt(0)), [budget, value])

  return (
    <div className='relative'>
      <button
        className='flex items-center py-2 space-x-1 text-sky-700 peer disabled:text-gray-400'
        disabled={assets.length <= 0}>
        <PlusIcon className='w-4' />
        <span>Add Asset</span>
      </button>
      <ul className='overflow-y-auto absolute z-50 max-h-64 text-sm bg-white rounded border divide-y shadow scale-0 peer-focus:scale-100 hover:scale-100'>
        {assets.map(([id, quantity]) => (
          <li key={id}>
            <button
              onClick={() => onSelect(id)}
              className='block p-2 w-full h-full hover:bg-sky-100'>
              <div className='flex space-x-2'>
                <span>{decodeASCII(getAssetName(id))}</span>
                <span>{quantity.toString()}</span>
              </div>
              <div className='flex space-x-1'>
                <span className='text-xs font-light'>{id.slice(0, 56)}</span>
              </div>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

const RecipientAddressInput: FC<{
  address: string
  cardano: Cardano
  className?: string
  disabled?: boolean
  setAddress: (address: string) => void
}> = ({ address, cardano, className, disabled, setAddress }) => {
  const [config, _] = useContext(ConfigContext)

  const isValid = cardano.isValidAddress(address) && isAddressNetworkCorrect(config, cardano.parseAddress(address))

  return (
    <div className={className}>
      <label className='block flex overflow-hidden rounded border ring-sky-500 focus-within:ring-1'>
        <span className='p-2 bg-gray-100 border-r'>To</span>
        <input
          className={['p-2 block w-full disabled:bg-gray-100', isValid ? '' : 'text-red-500'].join(' ')}
          disabled={disabled}
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder='Address' />
      </label>
      {address && !isValid && <p className='text-sm text-red-500'>The address is invalid.</p>}
    </div>
  )
}

const RecipientValueInput: FC<{
  className?: string
  value: Value
  setValue: (value: Value) => void
  minLovelace?: bigint
  budget: Value
}> = ({ className, value, setValue, minLovelace, budget }) => {
  const [config, _] = useContext(ConfigContext)
  const setLovelace = useCallback((lovelace: bigint) => {
    setValue({ ...value, lovelace })
  }, [value, setValue])
  const setAsset = useCallback((id: string, quantity: bigint) => {
    setValue({ ...value, assets: new Map(value.assets).set(id, quantity) })
  }, [value, setValue])
  const deleteAsset = useCallback((id: string) => {
    const newAssets = new Map(value.assets)
    newAssets.delete(id)
    setValue({ ...value, assets: newAssets })
  }, [value, setValue])
  const selectAsset = useCallback((id: string) => setAsset(id, BigInt(0)), [setAsset])

  return (
    <div className={className}>
      <div>
        <LabeledCurrencyInput
          symbol={getADASymbol(config)}
          decimal={6}
          value={value.lovelace}
          min={minLovelace}
          max={value.lovelace + budget.lovelace}
          onChange={setLovelace}
          placeholder='0.000000' />
        {minLovelace ? <p className='space-x-1 text-sm'>
          <span>At least</span>
          <button
            onClick={() => setLovelace(minLovelace)}
            className='font-semibold text-sky-700'>
            <ADAAmount lovelace={minLovelace} />
          </button>
          <span>is required</span>
        </p> : null}
      </div>
      <ul className='space-y-2'>
        {Array.from(value.assets).map(([id, quantity]) => {
          const symbol = decodeASCII(getAssetName(id))
          const assetBudget = (budget.assets.get(id) || BigInt(0))
          const onChange = (value: bigint) => setAsset(id, value)
          return (
            <li key={id} className='flex space-x-2'>
              <LabeledCurrencyInput
                symbol={symbol}
                decimal={0}
                value={quantity}
                max={quantity + assetBudget}
                maxButton={true}
                onChange={onChange} />
              <button className='p-2' onClick={() => deleteAsset(id)}>
                <XMarkIcon className='w-4' />
              </button>
            </li>
          )
        })}
      </ul>
      <AddAssetButton budget={budget} value={value} onSelect={selectAsset} />
    </div>
  )
}

const TransactionRecipient: FC<{
  cardano: Cardano
  recipient: Recipient
  budget: Value
  getMinLovelace: (recipient: Recipient) => bigint
  setRecipient: (recipient: Recipient) => void
}> = ({ cardano, recipient, budget, getMinLovelace, setRecipient }) => {
  const minLovelace = useMemo(() => cardano.isValidAddress(recipient.address) ? getMinLovelace(recipient) : undefined, [recipient, cardano, getMinLovelace])
  const setAddress = useCallback((address: string) => {
    setRecipient({ ...recipient, address })
  }, [setRecipient, recipient])
  const setValue = useCallback((value: Value) => {
    setRecipient({ ...recipient, value })
  }, [setRecipient, recipient])

  return (
    <div className='p-4 space-y-2'>
      <RecipientAddressInput address={recipient.address} setAddress={setAddress} cardano={cardano} />
      <RecipientValueInput className='space-y-2' value={recipient.value} setValue={setValue} budget={budget} minLovelace={minLovelace} />
    </div>
  )
}

const TransactionMessageInput: FC<{
  className?: string
  messageLines: string[]
  onChange: (messageLines: string[]) => void
}> = ({ className, messageLines, onChange }) => {
  const getLines = (text: string): string[] => text.split(/\r?\n/g)
  const changeHandle: ChangeEventHandler<HTMLTextAreaElement> = (event) => {
    onChange(getLines(event.target.value))
  }
  const isValid = messageLines.every((line) => new TextEncoder().encode(line).length <= 64)

  return (
    <textarea
      className={[className, isValid ? '' : 'text-red-500'].join(' ')}
      placeholder='Optional transaction message'
      rows={4}
      value={messageLines.join("\n")}
      onChange={changeHandle}>
    </textarea>
  )
}

const NewTransaction: FC<{
  cardano: Cardano
  protocolParameters: ProtocolParams
  utxos: TransactionOutput[]
  buildInputResult: (builder: SingleInputBuilder) => InputBuilderResult
  buildCertResult: (builder: SingleCertificateBuilder) => CertificateBuilderResult
  buildWithdrawalResult: (builder: SingleWithdrawalBuilder) => WithdrawalBuilderResult
  defaultChangeAddress: string
  rewardAddress: string
  availableReward: bigint
  isRegistered: boolean
  currentDelegation?: StakePool
}> = ({ cardano, protocolParameters, buildInputResult, buildCertResult, buildWithdrawalResult, rewardAddress, availableReward, utxos, defaultChangeAddress, isRegistered, currentDelegation }) => {
  const currentSlot = useLiveSlot()
  const [startSlot, setStartSlot] = useState<number | undefined>(currentSlot)
  const [expirySlot, setExpirySlot] = useState<number | undefined>(currentSlot + 24 * 60 * 60)
  const [recipients, setRecipients] = useState<Recipient[]>([newRecipient()])
  const [message, setMessage] = useState<string[]>([])
  const [inputs, setInputs] = useState<TransactionOutput[]>([])
  const [changeAddress, setChangeAddress] = useState<string>(defaultChangeAddress)
  const [isChangeSettingDisabled, setIsChangeSettingDisabled] = useState(true)
  const [willSpendAll, setWillSpendAll] = useState(false)
  const [minLovelaceForChange, setMinLovelaceForChange] = useState(BigInt(5e6))
  const [modal, setModal] = useState<'delegation' | 'start' | 'expiry' | undefined>()
  const [delegation, setDelegation] = useState<StakePool | undefined>()
  const deposit: bigint = useMemo(() => {
    if (!isRegistered && delegation) return BigInt(protocolParameters.keyDeposit)
    return BigInt(0)
  }, [isRegistered, delegation, protocolParameters])
  const [config, _] = useContext(ConfigContext)
  const donatingAddress = useMemo(() => donationAddress(config.network), [config.network])
  const [donatingValue, setDonatingValue] = useState<Value | undefined>()
  const donatingRecipient: Recipient | undefined = useMemo(() => donatingValue && {
    address: donatingAddress,
    value: donatingValue
  }, [donatingValue, donatingAddress])
  const allRecipients = useMemo(() => recipients.concat(donatingRecipient ?? []), [donatingRecipient, recipients])
  const budget: Value = useMemo(() => allRecipients
    .map(({ value }) => value)
    .concat({ lovelace: deposit, assets: new Map() })
    .reduce((result, value) => {
      const lovelace = result.lovelace - value.lovelace
      const assets = new Map(result.assets)
      Array.from(value.assets).forEach(([id, quantity]) => {
        const _quantity = assets.get(id)
        _quantity && assets.set(id, _quantity - quantity)
      })
      return { lovelace, assets }
    }, getBalanceByUTxOs(utxos)), [deposit, allRecipients, utxos])
  const donate = useCallback(() => {
    setDonatingValue({
      lovelace: BigInt(0),
      assets: new Map()
    })
  }, [])
  const stakeRegistration = useMemo(() => {
    if (!isRegistered && delegation) return cardano.createRegistrationCertificate(rewardAddress)
  }, [cardano, delegation, rewardAddress, isRegistered])
  const stakeDelegation = useMemo(() => {
    if (delegation) return cardano.createDelegationCertificate(rewardAddress, delegation.id)
  }, [cardano, delegation, rewardAddress])
  const [stakeDeregistration, setStakeDeregistration] = useState<Certificate | undefined>()
  const [withdrawAll, setWithdrawAll] = useState(false)

  useEffect(() => {
    if (stakeDeregistration) {
      setDelegation(undefined)
      availableReward > BigInt(0) && setWithdrawAll(true)
    }
  }, [availableReward, stakeDeregistration])

  const auxiliaryData = useMemo(() => {
    if (message.length > 0) {
      const { AuxiliaryData, MetadataJsonSchema } = cardano.lib
      const value = JSON.stringify({
        msg: message
      })
      let data = AuxiliaryData.new()
      // TODO
      // data.add_metadata(Metadata.new().).add_json_metadatum_with_schema(cardano.getMessageLabel(), value, MetadataJsonSchema.NoConversions)
      return data
    }
  }, [cardano, message])

  const closeModal = useCallback(() => setModal(undefined), [])
  const delegate = useCallback((stakePool: StakePool) => {
    setDelegation(stakePool)
    closeModal()
  }, [closeModal])
  const confirmStartSlot = useCallback((slot: number) => {
    setStartSlot(slot)
    closeModal()
  }, [closeModal])
  const confirmExpirySlot = useCallback((slot: number) => {
    setExpirySlot(slot)
    closeModal()
  }, [closeModal])
  useEffect(() => {
    if (isChangeSettingDisabled) {
      setChangeAddress(defaultChangeAddress)
      setWillSpendAll(false)
    }
  }, [defaultChangeAddress, isChangeSettingDisabled])

  useEffect(() => {
    if (willSpendAll || allRecipients.length === 0) {
      setInputs(utxos)
      return
    }

    setInputs([])

    init().then(() => {
      const inputs: Output[] = utxos.map((txOutput) => {
        return {
          data: txOutput,
          lovelace: BigInt(txOutput.value),
          assets: txOutput.tokens.map((token) => {
            const assetId = token.asset.assetId
            return {
              policyId: getPolicyId(assetId),
              assetName: getAssetName(assetId),
              quantity: BigInt(token.quantity)
            }
          })
        }
      })
      const outputs: Output[] = allRecipients.map((recipient) => {
        return {
          lovelace: recipient.value.lovelace,
          assets: Array.from(recipient.value.assets).map(([id, quantity]) => {
            return {
              policyId: getPolicyId(id),
              assetName: getAssetName(id),
              quantity: BigInt(quantity)
            }
          })
        }
      })
      const result = select(inputs, outputs, { lovelace: minLovelaceForChange, assets: [] })
      const txOutputs: TransactionOutput[] | undefined = result?.selected.map((output) => output.data)
      txOutputs && setInputs(txOutputs)
    })
  }, [utxos, allRecipients, willSpendAll, minLovelaceForChange])

  const getMinLovelace = useCallback((recipient: Recipient): bigint => cardano.getMinLovelace(recipient, protocolParameters), [cardano, protocolParameters])

  const txResult = useMemo(() => getResult(() => {
    if (inputs.length === 0) throw new Error('No UTxO is spent.')

    const { ChangeSelectionAlgo, SingleCertificateBuilder } = cardano.lib
    const txBuilder = cardano.createTxBuilder(protocolParameters)

    inputs.forEach((input) => {
      const builder = cardano.createTxInputBuilder(input)
      txBuilder.add_input(buildInputResult(builder))
    })

    allRecipients.forEach((recipient) => {
      const txOutput = cardano.buildTxOutput(recipient, protocolParameters)
      txBuilder.add_output(txOutput)
    })

    if (stakeRegistration) txBuilder.add_cert(buildCertResult(SingleCertificateBuilder.new(stakeRegistration)))
    if (stakeDeregistration) txBuilder.add_cert(buildCertResult(SingleCertificateBuilder.new(stakeDeregistration)))
    if (stakeDelegation) txBuilder.add_cert(buildCertResult(SingleCertificateBuilder.new(stakeDelegation)))

    if (withdrawAll) {
      const builder = cardano.createWithdrawalBuilder(rewardAddress, availableReward)
      if (!builder) throw new Error('Failed to create withdrawal builder')
      txBuilder.add_withdrawal(buildWithdrawalResult(builder))
    }

    if (auxiliaryData) txBuilder.add_auxiliary_data(auxiliaryData)

    if (startSlot) txBuilder.set_validity_start_interval(BigInt(startSlot))
    if (expirySlot) txBuilder.set_ttl(BigInt(expirySlot))

    return txBuilder.build(ChangeSelectionAlgo.Default, cardano.parseAddress(changeAddress)).build_unchecked()
  }), [allRecipients, cardano, changeAddress, auxiliaryData, protocolParameters, inputs, stakeRegistration, stakeDelegation, buildInputResult, buildCertResult, buildWithdrawalResult, startSlot, expirySlot, availableReward, rewardAddress, withdrawAll, stakeDeregistration])

  const changeRecipient = useCallback((index: number, recipient: Recipient) => {
    setRecipients(recipients.map((_recipient, _index) => index === _index ? recipient : _recipient))
  }, [recipients])

  const deleteRecipient = useCallback((index: number) => {
    setRecipients(recipients.filter((_, _index) => index !== _index))
  }, [recipients])

  return (
    <Panel>
      <ul>
        {recipients.map((recipient, index) =>
          <li key={index}>
            <header className='flex justify-between px-4 py-2 bg-gray-100'>
              <h2 className='font-semibold'>Recipient #{index + 1}</h2>
              <nav className='flex items-center'>
                <button onClick={() => deleteRecipient(index)}>
                  <XMarkIcon className='w-4' />
                </button>
              </nav>
            </header>
            <TransactionRecipient
              cardano={cardano}
              recipient={recipient}
              budget={budget}
              getMinLovelace={getMinLovelace}
              setRecipient={(rec) => changeRecipient(index, rec)} />
          </li>
        )}
      </ul>
      {donatingValue && <div>
        <header className='flex justify-between px-4 py-2 bg-gray-100'>
          <h2 className='flex items-center space-x-1 font-semibold'>
            <span>Donation</span>
            <HeartIcon className='w-4 text-pink-500' />
          </h2>
          <nav className='flex items-center'>
            <button onClick={() => setDonatingValue(undefined)}>
              <XMarkIcon className='w-4' />
            </button>
          </nav>
        </header>
        <div className='p-4 space-y-2'>
          <div className='space-y-1'>
            <div>We kindly suggest considering tipping the developer as it would greatly contribute to the development and quality of the project. Your support is highly appreciated. Thank you for your consideration.</div>
          </div>
          <div className='font-semibold'>{donatingAddress}</div>
          <RecipientValueInput
            className='space-y-2'
            value={donatingValue}
            setValue={setDonatingValue}
            budget={budget}
            minLovelace={donatingRecipient && getMinLovelace(donatingRecipient)} />
        </div>
      </div>}
      {withdrawAll && <div>
        <header className='flex justify-between px-4 py-2 bg-gray-100'>
          <h2 className='font-semibold'>Withdraw Reward</h2>
          <nav className='flex items-center'>
            <button onClick={() => setWithdrawAll(false)}>
              <XMarkIcon className='w-4' />
            </button>
          </nav>
        </header>
        <div className='p-4 space-y-1'>
          <div>{rewardAddress}</div>
          <div className='p-2 rounded border'>
            <ADAAmount lovelace={availableReward} />
          </div>
        </div>
      </div>}
      {stakeDeregistration && <div>
        <header className='flex justify-between px-4 py-2 bg-gray-100'>
          <h2 className='font-semibold'>Stake Deregistration</h2>
          <nav className='flex items-center'>
            <button onClick={() => setStakeDeregistration(undefined)}>
              <XMarkIcon className='w-4' />
            </button>
          </nav>
        </header>
        <div className='p-4 space-y-1'>
          <div>{rewardAddress}</div>
        </div>
      </div>}
      {delegation && <div>
        <header className='flex justify-between px-4 py-2 bg-gray-100'>
          <div>
            <h2 className='font-semibold'>Delegation</h2>
          </div>
          <nav className='flex items-center'>
            <button onClick={() => setDelegation(undefined)}>
              <XMarkIcon className='w-4' />
            </button>
          </nav>
        </header>
        <div className='p-4 space-y-2'>
          <div className='grid grid-cols-1 gap-2 lg:grid-cols-4'>
            {currentDelegation && <div className='space-y-1'>
              <strong className='font-semibold'>From</strong>
              <StakePoolInfo stakePool={currentDelegation} />
            </div>}
            <div className='space-y-1'>
              {currentDelegation && <strong className='font-semibold'>To</strong>}
              <StakePoolInfo stakePool={delegation} />
            </div>
          </div>
          {deposit > BigInt(0) && <p className='text-sm'>This address was not registered for staking. Will deposit <ADAAmount className='font-semibold' lovelace={deposit} /> to register.</p>}
        </div>
      </div>}
      <div>
        <header className='flex justify-between px-4 py-2 bg-gray-100'>
          <h2 className='font-semibold'>Lifetime</h2>
        </header>
        <div className='p-4 space-y-2'>
          <div className='flex items-center space-x-2'>
            <span>Start slot:</span>
            {startSlot ? <EditTimelockStart slot={startSlot} /> : <span>N/A</span>}
            <nav className='items-center text-xs text-sky-700 rounded border divide-x'>
              <button onClick={() => setModal('start')} className='px-2 py-1'>Change</button>
              <button onClick={() => setStartSlot(undefined)} className='px-2 py-1'>Remove</button>
            </nav>
            {modal === 'start' && <Modal className='p-4 space-y-1 bg-white rounded sm:w-full md:w-1/2 lg:w-1/3' onBackgroundClick={closeModal}>
              <h2 className='font-semibold'>Start Slot</h2>
              <SlotInput className='space-y-2' confirm={confirmStartSlot} cancel={closeModal} initialSlot={startSlot} />
            </Modal>}
          </div>
          <div className='flex items-center space-x-2'>
            <span>Expire slot:</span>
            {expirySlot ? <EditTimelockExpiry slot={expirySlot} /> : <span>N/A</span>}
            <nav className='items-center text-xs text-sky-700 rounded border divide-x'>
              <button onClick={() => setModal('expiry')} className='px-2 py-1'>Change</button>
              <button onClick={() => setExpirySlot(undefined)} className='px-2 py-1'>Remove</button>
            </nav>
            {modal === 'expiry' && <Modal className='p-4 space-y-1 bg-white rounded sm:w-full md:w-1/2 lg:w-1/3' onBackgroundClick={closeModal}>
              <h2 className='font-semibold'>Expiry Slot</h2>
              <SlotInput className='space-y-2' confirm={confirmExpirySlot} cancel={closeModal} initialSlot={startSlot} />
            </Modal>}
          </div>
        </div>
      </div>
      <div>
        <header className='px-4 py-2 bg-gray-100'>
          <h2 className='font-semibold'>{allRecipients.length > 0 ? 'Change' : 'Send All'}</h2>
          <p className='text-sm'>{allRecipients.length > 0 ? 'The change caused by this transaction or all remaining assets in the treasury will be sent to this address (default to the treasury address). DO NOT MODIFY IT UNLESS YOU KNOW WHAT YOU ARE DOING!' : 'All assets in this treasury will be sent to this address.'}</p>
          {allRecipients.length > 0 && <p>
            <label className='items-center space-x-1 text-sm'>
              <input
                type='checkbox'
                checked={!isChangeSettingDisabled}
                onChange={() => setIsChangeSettingDisabled(!isChangeSettingDisabled)} />
              <span>I know the risk and I want to do it.</span>
            </label>
          </p>}
        </header>
        <div className='p-4 space-y-2'>
          <RecipientAddressInput
            cardano={cardano}
            disabled={isChangeSettingDisabled && allRecipients.length > 0}
            address={changeAddress}
            setAddress={setChangeAddress} />
          {!willSpendAll && allRecipients.length > 0 && <div className='space-y-1'>
            <label className='block flex overflow-hidden rounded border ring-sky-500 focus-within:ring-1'>
              <span className='p-2 bg-gray-100 border-r'>Least Change ADA</span>
              <ADAInput
                disabled={isChangeSettingDisabled}
                className='p-2 grow disabled:bg-gray-100'
                lovelace={minLovelaceForChange}
                setLovelace={setMinLovelaceForChange} />
            </label>
            <div className='text-sm'>Default to 5. The more tokens you have the larger it needs to create transaction properly.</div>
          </div>}
          {!isChangeSettingDisabled && allRecipients.length > 0 && <div>
            <label className='items-center space-x-1'>
              <input
                type='checkbox'
                checked={willSpendAll}
                onChange={() => setWillSpendAll(!willSpendAll)} />
              <span>Send all remaining assets in the treasury to this address</span>
            </label>
          </div>}
        </div>
      </div>
      <div>
        <header className='px-4 py-2 bg-gray-100'>
          <h2 className='font-semibold'>Message</h2>
          <p className='text-sm'>Cannot exceed 64 bytes each line.</p>
        </header>
        <TransactionMessageInput
          className='block p-4 w-full ring-inset ring-sky-500 focus:ring-1'
          onChange={setMessage}
          messageLines={message} />
      </div>
      <footer className='flex items-center p-4 bg-gray-100'>
        <div className='grow'>
          {txResult.isOk && <p className='flex space-x-1'>
            <span>Fee:</span>
            <span><ADAAmount lovelace={BigInt(txResult.data.body().fee())} /></span>
          </p>}
          {!txResult.isOk && <p className='flex items-center space-x-1 text-red-500'>
            <XCircleIcon className='w-4 h-4' />
            <span>{txResult.message === 'The address is invalid.' ? 'Some addresses are invalid.' : txResult.message}</span>
          </p>}
        </div>
        <nav className='flex justify-end space-x-2'>
          <button
            disabled={!!donatingValue}
            onClick={donate}
            className='flex items-center p-2 space-x-1 text-pink-800 bg-pink-100 rounded border disabled:bg-gray-100 disabled:text-gray-400'>
            <HeartIcon className='w-4' />
            <span>Donate</span>
          </button>
          <button
            className='p-2 text-sky-700 rounded border'
            onClick={() => setRecipients(recipients.concat(newRecipient()))}>
            Add Recipient
          </button>
          <button
            disabled={withdrawAll || availableReward === BigInt(0)}
            className='p-2 text-sky-700 rounded border disabled:bg-gray-100 disabled:text-gray-400'
            onClick={() => setWithdrawAll(true)}>
            Withdraw
          </button>
          <button
            disabled={!isRegistered || !!stakeDeregistration}
            className='p-2 text-red-700 rounded border disabled:bg-gray-100 disabled:text-gray-400'
            onClick={() => isRegistered && setStakeDeregistration(cardano.createDeregistrationCertificate(rewardAddress))}>
            Deregister
          </button>
          <button
            disabled={!!stakeDeregistration}
            className='p-2 text-sky-700 rounded border disabled:bg-gray-100 disabled:text-gray-400'
            onClick={() => setModal('delegation')}>
            Delegate
          </button>
          {modal === 'delegation' && <Modal className='p-4 w-full bg-white rounded lg:w-1/2' onBackgroundClick={closeModal}>
            <StakePoolPicker className='space-y-2' delegate={delegate} />
          </Modal>}
          {txResult.isOk && <Link className='flex items-center p-2 space-x-1 text-white bg-sky-700 rounded' href={getTransactionPath(txResult.data)}>
            <span>Review</span>
            <ChevronRightIcon className='w-4' />
          </Link>}
        </nav>
      </footer>
    </Panel>
  )
}

const StakePoolPicker: FC<{
  className?: string
  delegate: (_: StakePool) => void
}> = ({ className, delegate }) => {
  const limit = 6
  const [id, setId] = useState('')
  const [page, setPage] = useState(1)
  const isIdBlank = id.trim().length === 0
  const { data } = useStakePoolsQuery(isIdBlank ? undefined : id)
  const stakePools = data?.stakePools

  return (
    <div className={className}>
      <h2 className='text-lg font-semibold'>Staking Pools</h2>
      <div className='flex overflow-hidden items-center rounded border ring-sky-500 focus-within:ring-1'>
        <input
          onChange={(e) => setId(e.target.value)}
          type='search'
          className='block p-2 grow'
          placeholder='Search by Pool ID' />
        <span className='p-2'>
          <MagnifyingGlassIcon className='w-4' />
        </span>
      </div>
      {stakePools && <ul className='grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3'>
        {stakePools.map((stakePool) => <li key={stakePool.id}><StakePoolInfo stakePool={stakePool} delegate={delegate} /></li>)}
      </ul>}
      {isIdBlank && data && <nav className='flex justify-between items-center'>
        <button
          className='px-2 py-1 text-sky-700 rounded border disabled:text-gray-100'
          onClick={() => setPage(page - 1)}
          disabled={page === 1}>
          <ChevronLeftIcon className='w-4' />
        </button>
        <button
          onClick={() => setPage(page + 1)}
          className='px-2 py-1 text-sky-700 rounded border'>
          <ChevronRightIcon className='w-4' />
        </button>
      </nav>}
    </div>
  )
}

type StakePoolMetaData = { name: string, description: string, ticker: string, homepage: string }

const fetchStakePoolMetaData = async (url: string): Promise<StakePoolMetaData> =>
  fetch(url)
    .then((response) => {
      if (!response.ok) throw new Error(`Failed to fetch ${URL}`)
      return response.json()
    }).catch((error) => console.error(error))

const StakePoolInfo: FC<{
  stakePool: StakePool
  delegate?: (_: StakePool) => void
}> = ({ delegate, stakePool }) => {
  const [metaData, setMetaData] = useState<StakePoolMetaData | undefined>()
  const [config, _] = useContext(ConfigContext)
  const isRetired = stakePool.retirements && stakePool.retirements.length > 0
  const { SMASH } = config
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const id: string = stakePool.hash
    const hash: string | undefined = stakePool.metadataHash
    const url = hash && new URL(['api/v1/metadata', id, hash].join('/'), SMASH)

    if (url) {
      setLoading(true)
      fetchStakePoolMetaData(url.toString())
        .then((data) => setMetaData(data))
        .finally(() => setLoading(false))
    }
  }, [stakePool, SMASH])

  return (
    <div className='rounded border divide-y shadow'>
      <header className='p-2 space-y-1'>
        <div className='text-sky-700'>
          {loading && <SpinnerIcon className='w-4 animate-spin' />}
          {!loading && metaData && <Link href={metaData.homepage} className='block truncate' target='_blank'>
            [<strong>{metaData.ticker}</strong>] {metaData.name}
          </Link>}
        </div>
        {!loading && !metaData && <div className='text-gray-700'>{isRetired ? 'Retired' : 'Unknown'}</div>}
        <div className='text-xs break-all'>{stakePool.id}</div>
      </header>
      <div className='p-2 space-y-1 text-sm'>
        <div>
          <div className='flex justify-between items-center space-x-1'>
            <span className='font-semibold'>Margin:</span>
            <span>{stakePool.margin * 100}%</span>
          </div>
          <div className='flex justify-between items-center space-x-1'>
            <span className='font-semibold'>Fixed Fees:</span>
            <ADAAmount lovelace={BigInt(stakePool.fixedCost)} />
          </div>
          <div className='flex justify-between items-center space-x-1'>
            <span className='font-semibold'>Pledge:</span>
            <ADAAmount lovelace={BigInt(stakePool.pledge)} />
          </div>
        </div>
        {delegate && <nav>
          <button
            className='block p-1 w-full text-sm text-white bg-sky-700 rounded border'
            onClick={() => delegate(stakePool)}>
            Delegate
          </button>
        </nav>}
      </div>
    </div>
  )
}

export { CIP30SignTxButton, SubmitTxButton, CopyVkeysButton, WalletInfo, TransactionViewer, NewTransaction, StakePoolInfo, TransactionLoader }
