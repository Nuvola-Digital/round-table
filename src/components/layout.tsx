import { useMemo, useContext, useEffect, useState, useCallback } from 'react'
import type { ChangeEventHandler, MouseEventHandler, KeyboardEvent, KeyboardEventHandler, FC, ReactNode } from 'react'
import ReactDOM from 'react-dom'
import Link from 'next/link'
import { CogIcon, FolderOpenIcon, HomeIcon, PencilSquareIcon, PlusIcon, UserGroupIcon, WalletIcon, XMarkIcon } from '@heroicons/react/24/solid'
import { ConfigContext, isMainnet } from '../cardano/config'
import { NotificationCenter, NotificationContext } from './notification'
import { useLiveQuery } from 'dexie-react-hooks'
import { db } from '../db'
import type { MultisigWallet, PersonalWallet, Policy } from '../db'
import { useRouter } from 'next/router'
import Image from 'next/image'
import { getBalanceByPaymentAddresses, sumValues, usePaymentAddressesQuery } from '../cardano/react-query-api'
import type { Value } from '../cardano/react-query-api'
import { ADAAmount } from './currency'
import { ChainProgress } from './time'
import { getMultisigWalletPath, getPersonalWalletPath } from '../route'
import { SpinnerIcon } from './status'
import { useCardanoMultiplatformLib } from '../cardano/multiplatform-lib'
import { ExportUserDataButton, ImportUserData } from './user-data'

const Toggle: FC<{
  isOn: boolean
  onChange: ChangeEventHandler<HTMLInputElement>
}> = ({ isOn, onChange }) => {
  return (
    <label className='cursor-pointer'>
      <input className='hidden peer' type='checkbox' checked={isOn} onChange={onChange} />
      <div className='flex items-center w-12 bg-gray-500 rounded-full border border-gray-500 peer-checked:bg-green-500 peer-checked:border-green-500 peer-checked:justify-end'>
        <div className='w-6 h-6 bg-white rounded-full'></div>
      </div>
    </label>
  )
}

const Panel: FC<{
  children: ReactNode
  className?: string
}> = ({ children, className }) => {
  return (
    <div className={['border-t-4 border-sky-700 bg-white rounded shadow overflow-hidden', className].join(' ')}>
      {children}
    </div>
  )
}

const CopyButton: FC<{
  className?: string
  children: ReactNode
  copied?: ReactNode
  disabled?: boolean
  content?: string
  ms?: number
}> = ({ children, copied, className, disabled, content, ms }) => {
  const [isCopied, setIsCopied] = useState(false)

  const click = useCallback(() => {
    if (!content) return
    navigator.clipboard.writeText(content)
    setIsCopied(true)
  }, [content])

  useEffect(() => {
    const timer = setTimeout(() => {
      if (isCopied) setIsCopied(false)
    }, ms)

    return () => {
      clearTimeout(timer)
    }
  }, [isCopied, ms])

  return (
    <button className={className} disabled={disabled || isCopied || !content} onClick={click}>
      {isCopied ? (copied ?? 'Copied!') : children}
    </button>
  )
}

const ShareCurrentURLButton: FC<{
  className?: string
  children: ReactNode
}> = ({ children, className }) => {
  const [currentURL, setCurrentURL] = useState<string | undefined>()
  useEffect(() => setCurrentURL(document.location.href), [])

  return (
    <CopyButton className={className} content={currentURL} ms={500}>
      {children}
    </CopyButton>
  )
}

const BackButton: FC<{
  className?: string
  children: ReactNode
}> = ({ children, className }) => {
  const router = useRouter()
  return <button className={className} onClick={() => router.back()}>{children}</button>;
}

const NavLink: FC<{
  className?: string
  children: ReactNode
  href: string
  onPageClassName: string
}> = ({ children, className, href, onPageClassName }) => {
  const router = useRouter()
  const isOnPage = useMemo(() => {
    const route = router.route
    const parentPaths = href.split('/')
    const currentPaths = route.split('/')
    return href === route || parentPaths.every((name, index) => name === currentPaths[index])
  }, [href, router.route])

  return (
    <Link href={href} className={[className, isOnPage ? onPageClassName : ''].join(' ')}>
      {children}
    </Link>
  )
}

const PrimaryBar: FC = () => {
  return (
    <aside className='flex flex-col items-center w-20 text-white bg-sky-900'>
      <NavLink
        href='/'
        onPageClassName='bg-sky-700'
        className='p-4 hover:bg-sky-700'>
        <HomeIcon className='w-12' />
      </NavLink>
      <div id='open-tx'>
        <OpenURL className='p-4 hover:bg-sky-700'>
          <FolderOpenIcon className='w-12' />
        </OpenURL>
      </div>
      <div id='config'>
        <ConfigModalButton className='p-4 hover:bg-sky-700'>
          <CogIcon className='w-12' />
        </ConfigModalButton>
      </div>
      <a className='p-4 hover:bg-sky-700' target='_blank' rel='noreferrer' href='https://discord.gg/BGuhdBXQFU'>
        <div style={{ height: '48px' }}>
          <Image src='/Discord-Logo-White.svg' width={48} height={48} alt='Discord Server'></Image>
        </div>
      </a>
      <a className='p-4 hover:bg-sky-700' target='_blank' rel='noreferrer' href='https://github.com/ADAOcommunity/round-table'>
        <svg className='w-12 fill-white' viewBox="0 0 1024 1024" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path fillRule="evenodd" clipRule="evenodd" d="M8 0C3.58 0 0 3.58 0 8C0 11.54 2.29 14.53 5.47 15.59C5.87 15.66 6.02 15.42 6.02 15.21C6.02 15.02 6.01 14.39 6.01 13.72C4 14.09 3.48 13.23 3.32 12.78C3.23 12.55 2.84 11.84 2.5 11.65C2.22 11.5 1.82 11.13 2.49 11.12C3.12 11.11 3.57 11.7 3.72 11.94C4.44 13.15 5.59 12.81 6.05 12.6C6.12 12.08 6.33 11.73 6.56 11.53C4.78 11.33 2.92 10.64 2.92 7.58C2.92 6.71 3.23 5.99 3.74 5.43C3.66 5.23 3.38 4.41 3.82 3.31C3.82 3.31 4.49 3.1 6.02 4.13C6.66 3.95 7.34 3.86 8.02 3.86C8.7 3.86 9.38 3.95 10.02 4.13C11.55 3.09 12.22 3.31 12.22 3.31C12.66 4.41 12.38 5.23 12.3 5.43C12.81 5.99 13.12 6.7 13.12 7.58C13.12 10.65 11.25 11.33 9.47 11.53C9.76 11.78 10.01 12.26 10.01 13.01C10.01 14.08 10 14.94 10 15.21C10 15.42 10.15 15.67 10.55 15.59C13.71 14.53 16 11.53 16 8C16 3.58 12.42 0 8 0Z" transform="scale(64)" />
        </svg>
      </a>
    </aside>
  )
}

const WalletLink: FC<{
  name: string
  href: string
  lovelace?: bigint
  isOnPage: boolean
  children?: ReactNode
}> = ({ name, href, lovelace, isOnPage, children }) => {
  const info = (
    <div className='flex justify-between items-center p-4 space-x-1 bg-inherit'>
      <div className='w-2/3'>
        <div className='truncate'>{name}</div>
        <div className='text-sm font-normal'>
          {lovelace !== undefined ? <ADAAmount lovelace={lovelace} /> : <SpinnerIcon className='w-4 animate-spin' />}
        </div>
      </div>
      <div>{children}</div>
    </div>
  )

  if (isOnPage) return (
    <div className='overflow-hidden font-semibold text-sky-700 bg-sky-100 rounded-l'>
      {info}
    </div>
  )

  return (
    <Link href={href} className='hover:bg-sky-700'>
      {info}
    </Link>
  )
}

const PersonalWalletListing: FC<{
  wallet: PersonalWallet
  balances?: Map<string, Value>
}> = ({ wallet, balances }) => {
  const cardano = useCardanoMultiplatformLib()
  const [config, _] = useContext(ConfigContext)
  const router = useRouter()
  const isOnPage: boolean = useMemo(() => router.query.personalWalletId === wallet.id.toString(), [router.query.personalWalletId, wallet.id])
  const addresses: string[] | undefined = useMemo(() => {
    if (!cardano) return
    return Array.from(wallet.personalAccounts.values())
      .flatMap((account) => cardano.getAddressesFromPersonalAccount(account, isMainnet(config)))
  }, [cardano, wallet.personalAccounts, config])
  const balance: Value | undefined = useMemo(() => {
    if (!addresses || !balances) return
    const values: Value[] = []
    addresses.forEach((address) => {
      const value = balances.get(address)
      if (value) values.push(value)
    })
    return sumValues(values)
  }, [addresses, balances])

  return (
    <WalletLink href={getPersonalWalletPath(wallet.id)} name={wallet.name} isOnPage={isOnPage} lovelace={balance?.lovelace}>
      <WalletIcon className='w-8' />
    </WalletLink>
  )
}

const MultisigWalletListing: FC<{
  wallet: MultisigWallet
  balance?: Value
}> = ({ wallet, balance }) => {
  const [config, _] = useContext(ConfigContext)
  const cardano = useCardanoMultiplatformLib()
  const router = useRouter()
  const lovelace = balance?.lovelace
  const isOnPage: boolean = useMemo(() => {
    const policyContent = router.query.policy
    if (typeof policyContent === 'string') {
      const policy: Policy = JSON.parse(policyContent)
      const id = cardano?.getPolicyAddress(policy, isMainnet(config)).to_bech32()
      if (id) return id === wallet.id
    }
    return false
  }, [cardano, config, router.query.policy, wallet.id])

  return (
    <WalletLink href={getMultisigWalletPath(wallet.policy)} name={wallet.name} isOnPage={isOnPage} lovelace={lovelace}>
      <UserGroupIcon className='w-8' />
    </WalletLink>
  )
}

const WalletList: FC = () => {
  const [config, _] = useContext(ConfigContext)
  const cardano = useCardanoMultiplatformLib()
  const multisigWallets = useLiveQuery(async () => db.multisigWallets.toArray())
  const personalWallets = useLiveQuery(async () => db.personalWallets.toArray())
  const addresses: string[] = useMemo(() => {
    const result = new Set<string>()
    if (!cardano) return []
    multisigWallets?.forEach(({ id }) => result.add(id))
    personalWallets?.forEach(({ personalAccounts }) => {
      personalAccounts.forEach((account) =>
        cardano.getAddressesFromPersonalAccount(account, isMainnet(config)).forEach((address) => result.add(address)))
    })
    return Array.from(result)
  }, [multisigWallets, personalWallets, config, cardano])
  const { data } = usePaymentAddressesQuery({
    addresses
  })
  const balances: Map<string, Value> | undefined = useMemo(() => {
    if (!data) return

    const balanceMap = new Map<string, Value>()
    data.paymentAddresses.forEach((paymentAddress) => {
      const address = paymentAddress.address
      const balance = getBalanceByPaymentAddresses([paymentAddress])
      balanceMap.set(address, balance)
    })

    return balanceMap
  }, [data])

  return (
    <aside className='flex overflow-y-auto flex-col items-center w-60 text-white bg-sky-800'>
      <nav className='w-full font-semibold'>
        <NavLink
          href='/new'
          onPageClassName='bg-sky-700'
          className='flex justify-center items-center p-4 space-x-1 w-full hover:bg-sky-700'>
          <PlusIcon className='w-4' />
          <span>New Wallet</span>
        </NavLink>
      </nav>
      <nav className='block w-full'>
        {personalWallets?.map((wallet) => <PersonalWalletListing key={wallet.id} wallet={wallet} balances={balances} />)}
        {multisigWallets?.map((wallet) => <MultisigWalletListing key={wallet.id} wallet={wallet} balance={balances?.get(wallet.id)} />)}
      </nav>
    </aside>
  )
}

const Hero: FC<{
  className?: string
  children: ReactNode
}> = ({ className, children }) => {
  return <div className={['rounded p-4 bg-sky-700 text-white shadow space-y-2', className].join(' ')}>{children}</div>;
}

const Portal: FC<{
  id: string
  children: ReactNode
}> = ({ id, children }) => {
  const [root, setRoot] = useState<HTMLElement | null>()

  useEffect(() => {
    setRoot(document.getElementById(id))
  }, [id])

  if (!root) return null

  return ReactDOM.createPortal(children, root)
}

const Layout: FC<{
  children: ReactNode
}> = ({ children }) => {
  const [config, _] = useContext(ConfigContext)

  return (
    <div className='flex h-screen'>
      <PrimaryBar />
      <WalletList />
      <div className='overflow-y-auto w-full bg-sky-100'>
        {!isMainnet(config) && <div className='p-1 text-center text-white bg-red-900'>You are using {config.network} network</div>}
        <div className='p-2 space-y-2 h-screen'>
          <ChainProgress />
          {children}
        </div>
      </div>
      <div id='modal-root'></div>
      <div className='flex flex-row-reverse'>
        <NotificationCenter className='fixed p-4 space-y-2 w-80' />
      </div>
    </div>
  )
}

const Modal: FC<{
  className?: string
  children: ReactNode
  onBackgroundClick?: MouseEventHandler<HTMLDivElement>
}> = ({ className, children, onBackgroundClick }) => {
  return (
    <Portal id='modal-root'>
      <div onClick={onBackgroundClick} className='flex absolute inset-0 justify-center items-center bg-black bg-opacity-50'>
        <div onClick={(e) => e.stopPropagation()} className={className}>
          {children}
        </div>
      </div>
    </Portal>
  )
}

const useEnterPressListener = (callback: (event: KeyboardEvent) => void): KeyboardEventHandler<HTMLInputElement | HTMLTextAreaElement> => useCallback((event) => {
  if (!event.shiftKey && event.key === 'Enter') {
    event.preventDefault()
    callback(event)
  }
}, [callback])

const ConfirmModalButton: FC<{
  className?: string
  children?: ReactNode
  disabled?: boolean
  message?: string
  onConfirm: () => void
}> = ({ className, children, onConfirm, message, disabled }) => {
  const [modal, setModal] = useState(false)
  const closeModal = useCallback(() => setModal(false), [])
  const confirm = useCallback(() => {
    onConfirm()
    closeModal()
  }, [closeModal, onConfirm])

  return (
    <>
      <button onClick={() => setModal(true)} className={className} disabled={disabled}>{children}</button>
      {modal && <Modal className='p-4 space-y-4 w-full text-sm bg-white rounded md:w-1/3 lg:w-1/4' onBackgroundClick={closeModal}>
        <h2 className='text-lg font-semibold text-center'>Please Confirm</h2>
        <div className='text-lg text-center'>{message}</div>
        <nav className='flex justify-end space-x-2'>
          <button className='p-2 text-sky-700 rounded border' onClick={closeModal}>Cancel</button>
          <button onClick={confirm} className={className} disabled={disabled}>{children}</button>
        </nav>
      </Modal>}
    </>
  )
}

const TextareaModalBox: FC<{
  onConfirm: (value: string) => void
  children: ReactNode
  placeholder?: string
}> = ({ onConfirm, children, placeholder }) => {
  const [value, setValue] = useState('')
  const pressEnter = useEnterPressListener(() => onConfirm(value))
  const onChange: ChangeEventHandler<HTMLTextAreaElement> = useCallback((event) => {
    setValue(event.target.value)
  }, [])

  return (
    <>
      <div>
        <textarea
          autoFocus={true}
          value={value}
          onChange={onChange}
          onKeyDown={pressEnter}
          rows={6}
          placeholder={placeholder}
          className='block p-2 w-full text-sm ring-inset ring-sky-500 focus:ring-1'>
        </textarea>
      </div>
      <button
        onClick={() => onConfirm(value)}
        disabled={!value}
        className='flex justify-center items-center p-2 space-x-1 w-full text-white bg-sky-700 disabled:text-gray-500 disabled:bg-gray-100'>
        {children}
      </button>
    </>
  )
}

const OpenURL: FC<{
  className?: string
  children: ReactNode
}> = ({ className, children }) => {
  const router = useRouter()
  const { notify } = useContext(NotificationContext)
  const [modal, setModal] = useState(false)
  const closeModal = useCallback(() => setModal(false), [])
  const openModal = useCallback(() => setModal(true), [])
  const confirm = useCallback((content: string) => {
    try {
      const url = new URL(content)
      const [_, objectType, objectContent] = url.pathname.split('/')
      if (objectType === 'multisig' || objectType === 'base64' || objectType === 'hex') {
        router.push(['', objectType, objectContent].join('/'))
        closeModal()
        return
      }
      throw new Error('Unknown URL')
    } catch (error: any) {
      if (error.name === 'TypeError') {
        router.push(['', 'hex', content].join('/'))
      } else {
        notify('error', error)
      }
    }
  }, [closeModal, router, notify])

  return (
    <>
      <button onClick={openModal} className={className}>{children}</button>
      {modal && <Modal className='w-80' onBackgroundClick={closeModal}>
        <div className='overflow-hidden bg-white rounded'>
          <h2 className='p-2 font-semibold text-center bg-gray-100'>Open Remote Content</h2>
          <TextareaModalBox placeholder='Transaction URL/Hex or multisig wallet URL' onConfirm={confirm}>
            <FolderOpenIcon className='w-4' />
            <span>Open</span>
          </TextareaModalBox>
        </div>
      </Modal>}
    </>
  )
}

const ConfigModalButton: FC<{
  className?: string
  children?: ReactNode
}> = ({ className, children }) => {
  const [config, setConfig] = useContext(ConfigContext)
  const [modal, setModal] = useState(false)
  const closeModal = useCallback(() => setModal(false), [])
  const openModal = useCallback(() => setModal(true), [])
  const switchAutoSync = useCallback(() => setConfig({ ...config , autoSync: !config.autoSync }), [config, setConfig])
  const [subTab, setSubTab] = useState<'basic' | 'data' | 'sync'>('basic')

  return (
    <>
      <button onClick={openModal} className={className}>{children}</button>
      {modal && <Modal className='w-160' onBackgroundClick={closeModal}>
        <div className='overflow-hidden p-4 space-y-2 text-sm bg-white rounded'>
          <div className='flex justify-between items-center'>
            <div className='flex overflow-hidden text-white bg-sky-700 rounded border border-sky-700 divide-x'>
              <button className='p-1 disabled:bg-white disabled:text-sky-700' onClick={() => setSubTab('basic')} disabled={subTab === 'basic'}>Basic</button>
              <button className='p-1 disabled:bg-white disabled:text-sky-700' onClick={() => setSubTab('data')} disabled={subTab === 'data'}>Data</button>
              <button className='p-1 disabled:bg-white disabled:text-sky-700' onClick={() => setSubTab('sync')} disabled={subTab === 'sync'}>Sync</button>
            </div>
            <button onClick={closeModal}><XMarkIcon className='w-6' /></button>
          </div>
          {subTab === 'basic' && <div className='space-y-2'>
            <div>
              <strong>Network</strong>
              <div>{config.network}</div>
            </div>
            
            {config.submitAPI && <div>
              <strong>Submit API</strong>
              <ul>
                {config.submitAPI.map((api, index) => <li key={index}>{api}</li>)}
              </ul>
            </div>}
          </div>}
          {subTab === 'data' && <div className='space-y-4'>
            <div>
              <strong>User Data Export/Import</strong>
              <div>User data has to be on the same network. For example, data exported from testnet cannot be imported to mainnet.</div>
              <div className='font-semibold text-red-500'>Data from V1 is not supported!</div>
            </div>
            <div className='space-y-2'>
              <div>
                <ExportUserDataButton />
              </div>
              <div className='font-semibold text-red-500'>Keep this file private!</div>
            </div>
            <div>
              <strong>Import User Data</strong>
              <ImportUserData />
            </div>
          </div>}
          {subTab === 'sync' && <div className='space-y-2'>
            <div>
              <strong>GUN Peers</strong>
              {config.gunPeers && <ul>
                {config.gunPeers.map((peer, index) => <li key={index}>{peer}</li>)}
              </ul>}
            </div>
            <div className='flex justify-between items-center'>
              <div className='font-semibold'>Auto Sync Signature</div>
              <Toggle isOn={config.autoSync} onChange={switchAutoSync} />
            </div>
          </div>}
        </div>
      </Modal>}
    </>
  )
}

const InlineEditInput: FC<{
  value: string
  setValue: (value: string) => void
  rows: number
}> = ({ value, setValue, rows }) => {
  const [inputValue, setInputValue] = useState(value)
  const [isEditable, setIsEditable] = useState(false)
  const editHandler = useCallback(() => {
    setInputValue(value)
    setIsEditable(true)
  }, [value])
  const blurHandler = useCallback(() => {
    setValue(inputValue)
    setIsEditable(false)
  }, [inputValue, setValue])
  const changeHandler: ChangeEventHandler<HTMLTextAreaElement> = useCallback((event) => setInputValue(event.target.value), [])

  if (isEditable) return (
    <textarea
      autoFocus={true}
      className='block p-2 w-full rounded border ring-sky-500 focus:ring-1 text-inherit'
      rows={rows}
      onBlur={blurHandler}
      onChange={changeHandler} value={inputValue} />
  )

  return (
    <>
      <span>{value}</span>
      <span><button className='p-1 text-sky-700' onClick={editHandler}><PencilSquareIcon className='w-4' /></button></span>
    </>
  )
}

export { Layout, Panel, Toggle, Hero, BackButton, CopyButton, ShareCurrentURLButton, Portal, Modal, ConfirmModalButton, useEnterPressListener, TextareaModalBox }
