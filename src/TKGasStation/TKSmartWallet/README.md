# TKSmartWallet

Two versions of the smart wallet and gas station exist. One version is for using passkeys with the fusaka upgrade, and one version is using just an arbitrary address you can point to

## Base Mainnet Deployments

### Passkey Smart Wallets

- **PasskeySmartWalletDelegate**: [`0x1a319349b1CA0E634B9f52ae41DeC34489D63dD9`](https://basescan.org/address/0x1a319349b1ca0e634b9f52ae41dec34489d63dd9)
- **PasskeySmartWalletFactory**: [`0xab78ee265a8581b50f3021ff109def8fd2464518`](https://basescan.org/address/0xab78ee265a8581b50f3021ff109def8fd2464518)
- **ImmutableSmartWalletGasStation (Passkey)**: [`0x5290a14036D05070cF0844eC685A9aab2e523Ae9`](https://basescan.org/address/0x5290a14036d05070cf0844ec685a9aab2e523ae9)

### Address Smart Wallets

- **AddressSmartWalletDelegate**: [`0x6E25166892285f9E9e776F2E7bE83C73Fb8A60FA`](https://basescan.org/address/0x6e25166892285f9e9e776f2e7be83c73fb8a60fa)
- **AddressSmartWalletFactory**: [`0xb0dc7e32c86f9255d2f21b66e272063c0ee06036`](https://basescan.org/address/0xb0dc7e32c86f9255d2f21b66e272063c0ee06036)
- **ImmutableSmartWalletGasStation (Address)**: [`0x82E7acb2335BC771813f1FBe4F26E52859307888`](https://basescan.org/address/0x82e7acb2335bc771813f1fbe4f26e52859307888)

## Ethereum Mainnet Deployments

### Passkey Smart Wallets

- **PasskeySmartWalletDelegate**: [`0x1a319349b1CA0E634B9f52ae41DeC34489D63dD9`](https://etherscan.io/address/0x1a319349b1ca0e634b9f52ae41dec34489d63dd9)
- **PasskeySmartWalletFactory**: [`0xab78ee265a8581b50f3021ff109def8fd2464518`](https://etherscan.io/address/0xab78ee265a8581b50f3021ff109def8fd2464518)
- **ImmutableSmartWalletGasStation (Passkey)**: [`0x5290a14036D05070cF0844eC685A9aab2e523Ae9`](https://etherscan.io/address/0x5290a14036d05070cf0844ec685a9aab2e523ae9)

### Address Smart Wallets

- **AddressSmartWalletDelegate**: [`0x6E25166892285f9E9e776F2E7bE83C73Fb8A60FA`](https://etherscan.io/address/0x6e25166892285f9e9e776f2e7be83c73fb8a60fa)
- **AddressSmartWalletFactory**: [`0xb0dc7e32c86f9255d2f21b66e272063c0ee06036`](https://etherscan.io/address/0xb0dc7e32c86f9255d2f21b66e272063c0ee06036)
- **ImmutableSmartWalletGasStation (Address)**: [`0x82E7acb2335BC771813f1FBe4F26E52859307888`](https://etherscan.io/address/0x82e7acb2335bc771813f1fbe4f26e52859307888)

All contracts were deployed using the Immutable Create2 Factory with salt `0x0000000000000000000000000000000000000000000000000000004761737379` ("Gassy").
