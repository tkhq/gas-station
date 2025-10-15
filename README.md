## TK Gas Station

TK Gas Station lets a user have all their gas paid for by another party using metatransactions.

### Deployments

#### Ethereum Mainnet
- **TKGasDelegate**: [0x1B2AfF879Ca5367Ee610C33EE9c8A335495E5688](https://etherscan.io/address/0x1b2aff879ca5367ee610c33ee9c8a335495e5688)
- **TKGasStation**: [0x9c3f5729BBDfb113c750Cf5e3EDBF56ba315CA57](https://etherscan.io/address/0x9c3f5729bbdfb113c750cf5e3edbf56ba315ca57)

#### Base Mainnet
- **TKGasDelegate**: [0xC2a37Ee08cAc3778d9d05FF0a93FD5B553C77E3a](https://basescan.org/address/0xc2a37ee08cac3778d9d05ff0a93fd5b553c77e3a)
- **TKGasStation**: [0x4ece92b06C7d2d99d87f052E0Fca47Fb180c3348](https://basescan.org/address/0x4ece92b06c7d2d99d87f052e0fca47fb180c3348)

#### Polygon Mainnet
- **TKGasDelegate**: [0x1B2AfF879Ca5367Ee610C33EE9c8A335495E5688](https://polygonscan.com/address/0x1b2aff879ca5367ee610c33ee9c8a335495e5688)
- **TKGasStation**: [0x9c3f5729BBDfb113c750Cf5e3EDBF56ba315CA57](https://polygonscan.com/address/0x9c3f5729bbdfb113c750cf5e3edbf56ba315ca57)

#### Sepolia Testnet
- **TKGasDelegate**: [0x1B2AfF879Ca5367Ee610C33EE9c8A335495E5688](https://sepolia.etherscan.io/address/0x1b2aff879ca5367ee610c33ee9c8a335495e5688)
- **TKGasStation**: [0x9c3f5729BBDfb113c750Cf5e3EDBF56ba315CA57](https://sepolia.etherscan.io/address/0x9c3f5729bbdfb113c750cf5e3edbf56ba315ca57)

#### Base Sepolia Testnet
- **TKGasDelegate**: [0x1B2AfF879Ca5367Ee610C33EE9c8A335495E5688](https://sepolia.basescan.org/address/0x1b2aff879ca5367ee610c33ee9c8a335495e5688)
- **TKGasStation**: [0x9c3f5729BBDfb113c750Cf5e3EDBF56ba315CA57](https://sepolia.basescan.org/address/0x9c3f5729bbdfb113c750cf5e3edbf56ba315ca57)

#### Polygon Amoy Testnet
- **TKGasDelegate**: [0x1B2AfF879Ca5367Ee610C33EE9c8A335495E5688](https://amoy.polygonscan.com/address/0x1b2aff879ca5367ee610c33ee9c8a335495e5688)
- **TKGasStation**: [0x9c3f5729BBDfb113c750Cf5e3EDBF56ba315CA57](https://amoy.polygonscan.com/address/0x9c3f5729bbdfb113c750cf5e3edbf56ba315ca57)

## Overall Flow
1. The user signs a type 4 transaction to delegate access to TKGasDelegate (EIP-7702). This can be broadcasted by the paymaster
2. The user then signs a metatransaction (EIP-712) to give permissions to the paymaster to initiate a transaction on behalf of the user
3. The paymaster then submits the metatransaction to the TKGasStation

## Security Design Decisions
* There are no re-entry protections by design. Re-entrancy should be guarded by the contracts the user is interacting with (as in a normal EoA)
    - The nonce for execute and batch execute will naturally protect against re-entrancy, but this should not be relied upon 
    - There is no built in re-entrancy protection for session based auth since it is meant to be replayed
* Both the delegate and the gas station are not using DRY. This is a purpsoseful design choice to save gas during run time
* Paymasters (and anyone else) can interact with TKGasDelegate through the TKGasStation or directly through the delegate itself
* The gas station has helper external functions for hashing for the type hash. This is just to help for external development and testing, and are not used during execution
* There are session metatransactions that give one particular wallet unlimited execution on behalf of a user
    - This is a footgun and should be used carefully
    - This limits to only one wallet in the typehash
    - Each one has a counter 
    - Multiple signatures (sessions) can be on a single counter
    - The counter is non sequential
    - The purpose of the counter is to act as a "log out" functionality to expire the session before the deadline - Burning this will invalidate all signatures with that counter 
* The standard execution metatransactions should limit by nonce, deadline, interacting contract, and arguments
* Batch transactions for standard execution should share one nonce per batch and one signature that includes the whole batch
* For session batch execution, only the session limitations of sender, counter, and deadline are verified. Not the batch
* All execute will revert if it gets a failure. Anything interacting with the gas station should be able to handle that
* Batch transactions are capped at 20 per batch currently
* Burning a nonce only burns the current nonce. Ones that are premade will be valid
* Nonces are sequential and can only be used sequentially
* A user can burn their own counter or nonce without a 712
* The gas delegate implements recievers for ERC-721 and ERC-1155
* The Gas station cannot use session based auth. This is because authorizing the gas station to send arbitrary messages would enable anyone to send arbitrary messages through the gas station
* The delegate does not implement EIP-7821[https://eips.ethereum.org/EIPS/eip-7821] as described since the execute function is _payable_. As a security measure to not drain the paymaster, no execute functions by design are allowed to be payable
* An attack that can be pulled off to reset/modify the nonce/counters is as follows:
    1. A user delegates and uses it as normal. The nonce iterates up
    2. The user then delegates to a contract that changes the nonce or resets it to 0 since that storage slot stays with the user's address, not the delegated contract
    3. The user then delegates back to TKGasDelegate
    4. Since the nonce is reset, old transactions can be replayed.
    This is accepted because we have a deadline transactions and on step 2, if you delegate to a malicious contract the attacker already has control.  

## Packing data for calling the fallback function

The fall back function can call the execute and session execution functions. It does not call the burn functions 

To use it:
The first byte should be a null byte 0x00
The second byte is a combination of the first nibble that acts as the function selector and the second nibble that acts as a boolean that says whether or not to return values or not
The eth value is 10 bytes, a uint80

Function selectors without to return or not:
* 00 - Execute
* 10 - ApproveThenExecute
* 20 - ExecuteBatch
* 30 - ExecuteSession
* 40 - ExecuteBatchSession
* 50 - ExecuteArbitrarySession
* 60 - ExecuteBatchArbitrarySession

For example, a normal execute with no return would be 0x00. A normal execute with a return would be 0x01. 
