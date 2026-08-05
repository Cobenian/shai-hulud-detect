// Ordinary web3 client code using a public RPC provider. Nothing malicious.
const RPC_URL = "https://eth-mainnet.nodereal.io/v1/<key>";
const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

export function makeProvider(fetchImpl) {
  return { url: RPC_URL, token: USDC, fetchImpl };
}
