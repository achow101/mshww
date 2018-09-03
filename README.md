## Multisig with Hardware wallets and Core

Sets up a multisig with multiple hardware wallets and Bitcoin Core.

This software handles communicating with Core and hardware wallets for signing and with getting addresses from a keypool

## How it works

When a wallet is created, a new Bitcoin Core watching only wallet (with private keys disabled) is created. This wallet holds all of the imported scripts and public keys. Keys are taken from the specified Core wallet and hardware devices. These keys are used to create a multisig address which is imported into the watching only wallet. The watching only wallet is then used to construct PSBTs and given to the hardware devices and the Core wallet to sign when a send is done.
