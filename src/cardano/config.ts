import { createContext } from 'react'

type Network = 'mainnet' | 'testnet' | 'preview'

const parseNetwork = (text: string): Network => {
  switch (text) {
    case 'mainnet': return 'mainnet'
    case 'testnet': return 'testnet'
    case 'preview': return 'preview'
    default: throw new Error('Unknown network')
  }
}

type Config = {
  network: Network
  submitAPI: string[]
  SMASH: string
  gunPeers: string[]
  autoSync: boolean
}

const isMainnet = (config: Config) => config.network === 'mainnet'

const defaultSMASHMainnet = 'https://mainnet-smash.panl.org'
const defaultSMASHTestnet = 'https://preview-smash.panl.org'
const defaultSubmitURI = new URL(process.env.NEXT_PUBLIC_BACKEND_API || 'https://blockfrost-backend.com').toString() + "/submit-transaction/";

const defaultConfig: Config = {
  network: 'mainnet',
  submitAPI: [defaultSubmitURI],
  SMASH: defaultSMASHMainnet,
  gunPeers: [],
  autoSync: true,
}



const createConfig = (): Config => {
  const network = parseNetwork(process.env.NEXT_PUBLIC_NETWORK ?? 'mainnet')
  const defaultSMASH = network === 'mainnet' ? defaultSMASHMainnet : defaultSMASHTestnet
  const SMASH = process.env.NEXT_PUBLIC_SMASH ?? defaultSMASH
  const gunPeers = (process.env.NEXT_PUBLIC_GUN ?? '').split(';')

  return {
    network,
    submitAPI: [defaultSubmitURI],
    SMASH,
    gunPeers,
    autoSync: true
  }
}

const config = createConfig()

const ConfigContext = createContext<[Config, (x: Config) => void]>([defaultConfig, (_) => {}])


const donationAddress = (network: Network): string => {
  switch(network) {
    case 'mainnet':
      return 'addr1qy8yxxrle7hq62zgpazaj7kj36nphqyyxey62wm694dgfds5kkvr22hlffqdj63vk8nf8rje5np37v4fwlpvj4c4qryqtcla0w';
    default:
      return 'addr_test1qpe7qk82nqyd77tdqmn6q7y5ll4kwwxdajgwf3llcu4e44nmcxl09wnytjsykngrga52kqhevzv2dn67rt0876qmwn3sf7qxv3';
  }
}

export type { Config, Network }
export { ConfigContext, config, donationAddress, isMainnet }
