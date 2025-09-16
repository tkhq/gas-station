## TK Gas Station

TK Gas Station lets a user have all their gas paid for by another party using metatransactions.

## Overall Flow
1. The user signs a type 4 transaction to delegate access to TKGasDelegate (EIP-7702). This can be broadcasted by the paymaster
2. The user then signs a metatransaction (EIP-712) to give permissions to the paymaster to initiate a transaction on behalf of the user
3. The paymaster then submits the metatransaction to the TKGasStation

## Security Design Decisions
* There are no re-entry protections by design. Re-entrancy should be guarded by the contracts the user is interacting with (as in a normal EoA)
* Paymasters (and anyone else) can only interact with TKGasDelegate through the TKGasStation
* There are timeboxed metatransactions that give one particular wallet unlimited execution on behalf of a user
    - This is a footgun and should be used carefully
    - This limits to only one wallet in the typehash
    - Each one has a counter (starting at 0). Multiple signatures (sessions) can be on a single counter, but the counter is sequential
    - The purpose of the counter is to act as a "log out" functionality to expire the timeboxed session before the deadline. Burning this will invalidate all signatures with that counter 
* The standard execution metatransactions should limit by nonce, interacting contract, and arguments
* Batch transactions for standard execution should share one nonce per batch and one signature that includes the whole batch
* For timeboxed batch execution, only the timeboxed limitations of sender, counter, and deadline are verified. Not the batch
* All execute will revert if it gets a failure. Anything interacting with the gas station should be able to handle that
* Batch transactions are capped at 50 per batch currently
