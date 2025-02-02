import { useLiveQuery } from 'dexie-react-hooks'
import type { NextPage } from 'next'
import { useRouter } from 'next/router'
import { useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { FC, ChangeEventHandler } from 'react'
import { ConfirmModalButton, Hero, Layout, Modal, Panel, Portal } from '../../components/layout'
import { AskPasswordModalButton } from '../../components/password'
import { Loading, PartialLoading } from '../../components/status'
import { db, deletePersonalWallet, updatePersonalWallet, updatePersonalWalletAndDeindex } from '../../db'
import type { PersonalWallet } from '../../db'
import { useCardanoMultiplatformLib } from '../../cardano/multiplatform-lib'
import type { Cardano } from '../../cardano/multiplatform-lib'
import { ConfigContext, isMainnet } from '../../cardano/config'
import { ExclamationTriangleIcon } from '@heroicons/react/24/solid'
import { NotificationContext } from '../../components/notification'
import { DerivationPath, RemoveWallet, Summary } from '../../components/wallet'
import { getAvailableReward, isRegisteredOnChain, useUTxOSummaryQuery } from '../../cardano/react-query-api'
import { NewTransaction } from '../../components/transaction'
import { SingleCertificateBuilder, SingleInputBuilder, SingleWithdrawalBuilder } from '@dcspark/cardano-multiplatform-lib-browser'
import { AddressableContent } from '../../components/address'

const AddressTable: FC<{
  addresses: string[]
  addressName: string
}> = ({ addresses, addressName }) => {
  const cardano = useCardanoMultiplatformLib()

  return (
    <table className='w-full text-left table-auto'>
      <thead className='bg-gray-100'>
        <tr>
          <th className='p-4'>{addressName}</th>
          <th className='p-4'>Payment Derivation Path</th>
          <th className='p-4'>Staking Derivation Path</th>
        </tr>
      </thead>
      <tbody className='text-sm divide-y'>
        {addresses.map((address) => <tr key={address}>
          <td className='items-center px-4 py-2'>
            <AddressableContent content={address} scanType='address' />
          </td>
          <td className='px-4 py-2'><DerivationPath keyHash={cardano?.parseAddress(address).payment_cred()?.as_pub_key()?.to_raw_bytes()} /></td>
          <td className='px-4 py-2'><DerivationPath keyHash={cardano?.parseAddress(address).staking_cred()?.as_pub_key()?.to_raw_bytes()} /></td>
        </tr>)}
      </tbody>
    </table>
  )
}

const Multisig: FC<{
  wallet: PersonalWallet
}> = ({ wallet }) => {
  const cardano = useCardanoMultiplatformLib()
  const [config, _] = useContext(ConfigContext)
  const accountIndex = 0
  const account = useMemo(() => wallet.multisigAccounts.get(accountIndex), [wallet.multisigAccounts, accountIndex])
  const addresses = useMemo(() => account && cardano?.getAddressesFromMultisigAccount(account, isMainnet(config)), [cardano, account, config])

  if (!cardano || !addresses) return (
    <Modal><Loading /></Modal>
  )

  const addAddress = () => {
    const indices = cardano.generateMultisigAddress(wallet, accountIndex)
    updatePersonalWallet(wallet, indices)
  }

  return (
    <Panel>
      <AddressTable addresses={addresses} addressName='Address for multisig' />
      <footer className='flex justify-end p-4 bg-gray-100'>
        <button onClick={addAddress} className='flex px-4 py-2 space-x-1 text-white bg-sky-700 rounded'>
          Add Address
        </button>
      </footer>
    </Panel>
  )
}

const Edit: FC<{
  wallet: PersonalWallet
}> = ({ wallet }) => {
  const [name, setName] = useState(wallet.name)
  const [description, setDescription] = useState(wallet.description)
  const { notify } = useContext(NotificationContext)

  useEffect(() => {
    setName(wallet.name)
    setDescription(wallet.description)
  }, [wallet])

  const canSave = name.length > 0

  const save = () => {
    db
      .personalWallets
      .update(wallet.id, { name, description, updatedAt: new Date() })
      .catch(() => notify('error', 'Failed to save'))
  }

  return (
    <Panel>
      <div className='p-4 space-y-4'>
        <label className='block space-y-1'>
          <div className="after:content-['*'] after:text-red-500">Name</div>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className='block p-2 w-full rounded border ring-sky-500 focus:ring-1'
            placeholder='Write Name' />
        </label>
        <label className='block space-y-1'>
          <div>Description</div>
          <textarea
            className='block p-2 w-full rounded border ring-sky-500 focus:ring-1'
            placeholder='Describe the wallet'
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}>
          </textarea>
        </label>
      </div>
      <footer className='flex justify-end p-4 bg-gray-100'>
        <button
          className='px-4 py-2 text-white bg-sky-700 rounded disabled:border disabled:text-gray-400 disabled:bg-gray-100'
          disabled={!canSave}
          onClick={save}>
          Save
        </button>
      </footer>
    </Panel>
  )
}

const Spend: FC<{
  addresses: string[]
  rewardAddress: string
  cardano: Cardano
}> = ({ addresses, rewardAddress, cardano }) => {
  const { isLoading:loading, error, data } = useUTxOSummaryQuery({
    addresses, rewardAddress 
  })
  const defaultChangeAddress = useMemo(() => {
    const address = addresses[0]
    if (!address) throw new Error('No address is found for change')
    return address
  }, [addresses])
  const buildResult = useCallback((builder: SingleInputBuilder | SingleCertificateBuilder | SingleWithdrawalBuilder) => builder.payment_key(), [])

  if (error) {
    console.error(error)
    return null
  }
  if (loading || !data) return (
    <PartialLoading />
  )

  const protocolParameters = data.cardano.currentEpoch.protocolParams
  if (!protocolParameters) throw new Error('No protocol parameter')
  const { stakeRegistrations_aggregate, stakeDeregistrations_aggregate, delegations } = data
  const isRegistered = isRegisteredOnChain(stakeRegistrations_aggregate, stakeDeregistrations_aggregate)
  const currentStakePool = isRegistered ? delegations[0]?.stakePool : undefined
  const availableReward = getAvailableReward(data.rewards_aggregate, data.withdrawals_aggregate)

  return (
    <NewTransaction
      isRegistered={isRegistered}
      currentDelegation={currentStakePool}
      cardano={cardano}
      buildInputResult={buildResult}
      buildCertResult={buildResult}
      buildWithdrawalResult={buildResult}
      rewardAddress={rewardAddress}
      availableReward={availableReward}
      protocolParameters={protocolParameters}
      utxos={data.utxos}
      defaultChangeAddress={defaultChangeAddress} />
  )
}

const Personal: FC<{
  wallet: PersonalWallet
  className?: string
}> = ({ wallet, className }) => {
  const cardano = useCardanoMultiplatformLib()
  const [config, _] = useContext(ConfigContext)
  const { notify } = useContext(NotificationContext)
  const [accountIndex, setAccountIndex] = useState(0)
  const account = useMemo(() => wallet.personalAccounts.get(accountIndex), [wallet.personalAccounts, accountIndex])
  const addresses = useMemo(() => account && cardano?.getAddressesFromPersonalAccount(account, isMainnet(config)), [cardano, account, config])
  const rewardAddress = useMemo(() => account && cardano?.readRewardAddressFromPublicKey(account.publicKey, isMainnet(config)).to_address().to_bech32(), [cardano, config, account])
  const [tab, setTab] = useState<'summary' | 'receive' | 'spend'>('summary')
  const selectAccount: ChangeEventHandler<HTMLSelectElement> = useCallback((e) => setAccountIndex(parseInt(e.target.value)), [])

  const addAddress = useCallback(() => {
    if (!cardano) return
    const indices = cardano.generatePersonalAddress(wallet, accountIndex)
    updatePersonalWallet(wallet, indices)
  }, [cardano, wallet, accountIndex])

  const addAccount = useCallback(async (password: string) => {
    if (!cardano) return
    const keys = Array.from(wallet.personalAccounts.keys())
    const newAccountIndex = Math.max(...keys) + 1
    cardano.generatePersonalAccount(wallet, password, newAccountIndex).then((indices) => {
      return updatePersonalWallet(wallet, indices)
    })
      .then(() => setAccountIndex(newAccountIndex))
      .catch(() => notify('error', 'Failed to add account'))
  }, [cardano, notify, wallet])

  const deleteAccount = useCallback(() => {
    if (!account) return
    const keyHashes = account.paymentKeyHashes
    wallet.personalAccounts.delete(accountIndex)
    updatePersonalWalletAndDeindex(wallet, keyHashes)
      .then(() => setAccountIndex(0))
  }, [account, accountIndex, wallet])

  if (!addresses || !rewardAddress || !cardano) return (
    <Modal><Loading /></Modal>
  )

  return (
    <div className={className}>
      <Portal id='personal-subtab'>
        <div className='flex space-x-2'>
          <nav className='overflow-hidden text-sm rounded border border-white divide-x'>
            <button
              onClick={() => setTab('summary')}
              disabled={tab === 'summary'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Summary
            </button>
            <button
              onClick={() => setTab('receive')}
              disabled={tab === 'receive'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Receive
            </button>
            <button
              onClick={() => setTab('spend')}
              disabled={tab === 'spend'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Spend
            </button>
          </nav>
          <nav className='overflow-hidden text-sm rounded border border-white divide-x'>
            <select value={accountIndex} onChange={selectAccount} className='px-2 py-1 bg-sky-700'>
              {Array.from(wallet.personalAccounts, ([index, _]) => <option key={index} value={index}>
                Account #{index}
              </option>)}
            </select>
            <AskPasswordModalButton title={wallet.name} onConfirm={addAccount} className='px-2 py-1'>
              Add Account
            </AskPasswordModalButton>
          </nav>
        </div>
      </Portal>
      {tab === 'summary' && <Summary addresses={addresses} rewardAddress={rewardAddress}>
        <footer className='flex justify-end p-4 bg-gray-100'>
          <ConfirmModalButton
            disabled={accountIndex === 0}
            onConfirm={deleteAccount}
            message={'Do you really want to remove Account #' + accountIndex}
            className='px-4 py-2 text-white bg-red-700 rounded disabled:border disabled:text-gray-400 disabled:bg-gray-100'>
            REMOVE
          </ConfirmModalButton>
        </footer>
      </Summary>}
      {tab === 'receive' && <Panel>
        <AddressTable addressName='Receiving Address' addresses={addresses} />
        <footer className='flex justify-end p-4 bg-gray-100'>
          <button onClick={addAddress} className='flex px-4 py-2 space-x-1 text-white bg-sky-700 rounded'>
            Add Address
          </button>
        </footer>
      </Panel>}
      {tab === 'spend' && <Spend addresses={addresses} rewardAddress={rewardAddress} cardano={cardano} />}
    </div>
  )
}

const ShowPersonalWallet: NextPage = () => {
  const router = useRouter()
  const personalWallet = useLiveQuery(async () => {
    const id = router.query.personalWalletId
    if (typeof id !== 'string') return
    return db.personalWallets.get(parseInt(id))
  }, [router.query.personalWalletId])
  const [tab, setTab] = useState<'personal' | 'multisig' | 'edit' | 'remove'>('personal')
  const { notify } = useContext(NotificationContext)

  const removeWallet = useCallback(() => {
    if (!personalWallet) return
    deletePersonalWallet(personalWallet)
      .then(() => router.push('/'))
      .catch((error) => {
        notify('error', 'Failed to delete')
        console.error(error)
      })
  }, [notify, personalWallet, router])

  if (!personalWallet) return (
    <Modal><Loading /></Modal>
  )

  return (
    <Layout>
      <Hero>
        <h1 className='text-lg font-semibold'>{personalWallet.name}</h1>
        <div>{personalWallet.description}</div>
        <div className='flex'>
          <nav className='overflow-hidden text-sm rounded border border-white divide-x'>
            <button
              onClick={() => setTab('personal')}
              disabled={tab === 'personal'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Personal
            </button>
            <button
              onClick={() => setTab('multisig')}
              disabled={tab === 'multisig'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Multisig
            </button>
            <button
              onClick={() => setTab('edit')}
              disabled={tab === 'edit'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Edit
            </button>
            <button
              onClick={() => setTab('remove')}
              disabled={tab === 'remove'}
              className='px-2 py-1 disabled:bg-white disabled:text-sky-700'>
              Remove
            </button>
          </nav>
        </div>
        {tab === 'personal' && <div className='flex' id='personal-subtab'></div>}
      </Hero>
      {tab === 'personal' && <Personal wallet={personalWallet} className='space-y-2' />}
      {tab === 'multisig' && <>
        <div className='flex items-center p-4 space-x-1 text-yellow-700 bg-yellow-100 rounded shadow'>
          <ExclamationTriangleIcon className='w-4' />
          <div>These addresses are only for multisig wallet making.</div>
          <strong className='font-semibold'>DO NOT USE THEM TO RECEIVE FUNDS.</strong>
        </div>
        <Multisig wallet={personalWallet} />
      </>}
      {tab === 'edit' && <Edit wallet={personalWallet} />}
      {tab === 'remove' && <RemoveWallet walletName={personalWallet.name} remove={removeWallet} />}
    </Layout>
  )
}

export default ShowPersonalWallet
