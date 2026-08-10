# keyv-c2-rotation-clean

False-positive guard for the keyv-wave C2-rotation IoCs.

NodeReal is a legitimate infrastructure provider and `eth-mainnet.nodereal.io`
is an ordinary public Ethereum RPC endpoint used by real dapps and wallet
tooling. It must not be flagged on its own — only alongside another wave
marker. The disclosed IoC is specifically an `eth-mainnet.nodereal[.]io`
request *containing* the rotation contract address.

This fixture is ordinary web3 client code and must stay clean.
