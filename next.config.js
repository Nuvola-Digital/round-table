/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    domains: ['gerowallet.io', '']
  },
  webpack(config, { dev, isServer }) {
    config.experiments = {
      asyncWebAssembly: true,
      syncWebAssembly: true,
      layers: true
    }


    if (isServer) {
      config.output.webassemblyModuleFilename =
        './../static/wasm/[modulehash].wasm';
    } else {
      config.output.webassemblyModuleFilename =
        'static/wasm/[modulehash].wasm';
    }
    return config
  }
}

module.exports = nextConfig
