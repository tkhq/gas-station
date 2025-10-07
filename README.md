## TK Gas Station

TK Gas Station lets a user have all their gas paid for by another party using metatransactions.

### Deployments

TKGasStationV1: 0x82c34aF30D1d0F9f977a0D3C014E6534AA945b41
TKGasDelegate (for V1): 0x84Dd9FEC95476FDa20DAD528cc50A36DC2Bb4481

TKGasStationV2: 0xBbb7F4d7758aD153f4C37F1c89948A656736643B 

## Overall Flow
1. The user signs a type 4 transaction to delegate access to TKGasDelegate (EIP-7702). This can be broadcasted by the paymaster
2. The user then signs a metatransaction (EIP-712) to give permissions to the paymaster to initiate a transaction on behalf of the user
3. The paymaster then submits the metatransaction to the TKGasStation

## Security Design Decisions
* There are no re-entry protections by design. Re-entrancy should be guarded by the contracts the user is interacting with (as in a normal EoA)
    - The nonce for execute and batch execute will naturally protect against re-entrancy, but this should not be relied upon 
    - There is no built in re-entrancy protection for session based auth since it is meant to be replayed
* Both the delegate and the gas station are not using DRY to avoid doing internal calls. This is a purpsoseful design choice to save gas during run time
* Paymasters (and anyone else) can only interact with TKGasDelegate through the TKGasStation
* The gas station has helper external functions for hashing for the type hash. This is just to help for external development and testing, and are not used during execution
* There are session metatransactions that give one particular wallet unlimited execution on behalf of a user
    - This is a footgun and should be used carefully
    - This limits to only one wallet in the typehash
    - Each one has a counter (starting at 0). Multiple signatures (sessions) can be on a single counter, but the counter is sequential
    - The purpose of the counter is to act as a "log out" functionality to expire the session before the deadline. Burning this will invalidate all signatures with that counter 
* The standard execution metatransactions should limit by nonce, interacting contract, and arguments
* Batch transactions for standard execution should share one nonce per batch and one signature that includes the whole batch
* For session batch execution, only the session limitations of sender, counter, and deadline are verified. Not the batch
* All execute will revert if it gets a failure. Anything interacting with the gas station should be able to handle that
* Batch transactions are capped at 50 per batch currently
* Burning a nonce or a counter only burns the current nonce/counter. Ones that are premade will be valid
* Nonces and session counters are sequential and can only be used sequentially
* A user can burn their own counter or nonce without a 712
* The gas delegate implements recievers for ERC-721 and ERC-1155
* The Gas station cannot use session based auth. This is because authorizing the gas station to send arbitrary messages would enable anyone to send arbitrary messages through the gas station
* The delegate does not implement EIP-7821[https://eips.ethereum.org/EIPS/eip-7821] as described since the execute function is _payable_. As a security measure to not drain the paymaster, no execute functions by design are allowed to be payable


## Packing data for calling the fallback function

The fall back function can call the execute and session execution functions. It does not call the burn functions 

To use it:
The first byte should be a null byte 0x00
The second byte is a combination of the first nibble that acts as the function selector and the second nibble that acts as a boolean that says whether or not to return values or not
The eth value must be exactly 10 bytes, since it will be treated as a uint80
Otherwise the order is exactly the same, simply encode it packed and it will parse for you

Function selectors:
* 00 - ExecuteNoValue no return
* 01 - ExecuteNoValue does return
* 10 - Execute with value no return
* 11 - Execute with value does return
* 20 - Approve then execute no return
* 21 - Approve then execute with return
* 30 - Batch execute no return
* 31 - Batch execute with return
* 40
* 50
* 60
* 70 
