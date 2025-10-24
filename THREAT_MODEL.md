# What is it? 
The gas station & gas delegate enable a paymaster to sponsor transactions on EIP-7702 compatible chains for customers. 
This implementation is expected to be gas efficient enough to be usable on mainnet. 
On chain authorization to protect the user is handled by EIP-712 metatransactions.
Protections for the paymaster to not pay for bad transactions is expected to mostly happen offchain.

## Difference between the delegate and the gas station
The delegate does all the necessary authorization checks to protect the user such as:
- Validate the EIP-712 signature
- Validate the nonce or counter
- Validate the deadline for the transaction
- In session mode only, validate that the msg.sender is allowed to initiate the transaction

The gas station is just a helper for the paymaster to have:
- A single interaction contract
- An on-chain verification step to ensure that the transaction that the paymaster will pay for is using the gas delegate (This can be done off-chain too)
- Limited functionality to only what our current paymaster implementation will use
- View functions to make it easier to see into contracts that have delegated to the gas delegate
In the future, there may be new gas stations that have extra functionality, but this one will only do the execution mode. 

## Transaction Flow
![Transaction Flow Diagram](./flow.png)
### Init contract (Once per chain, done with create2)
1. Gas delegate is deployed
2. Gas station is deployed with the gas delegate as an immutable

### User sign up (Once per chain per user)
1. User wallet signs a type-4 transaction giving the gas delegate authority
2. Paymaster broadcasts/pays for that transaction 

### Send a transaction (Once per transaction or session)
1. User wallet signs a metatransaction allowing the paymaster to initiate a transaction
2. The paymaster validates the transaction as somthing it wants to pay for off-chain
3. The transaction is initiated and paid for by the paymaster on chain 

## Modes
It has two modes:
1. A single action mode called "execution" that initiates one transaction with a consecutive nonce and a deadline
2. A replayable mode called "session" with a non-consecutive counter and a deadline

## Execution Mode 
Execution mode is limited by:
- uint128 consecutive nonce 
- uint32 deadline 
- execution data

The signature must evaluate before the deadline, be on the current nonce, and validate the execution data. Anyone can initiate and pay for this transaction

The signature types that execution mode have are:
1. Execution(uint128 nonce,uint32 deadline,address outputContract,uint256 ethAmount,bytes arguments) - normal execution
2. ApproveThenExecute(uint128 nonce,uint32 deadline,address erc20Contract,address spender,uint256 approveAmount,address outputContract,uint256 ethAmount,bytes arguments) - special case for approve then do a transferFrom on erc20
3. BatchExecution(uint128 nonce,uint32 deadline,Call[] calls)Call(address to,uint256 value,bytes data) - batch execution 
4. BurnNonce(uint128 nonce) - burns the nonce. Not limited by deadline. 

## Session Mode

Session mode is limited by:
- uint128 non-consecutive counter (does not get consumed on each transaction)
- uint32 deadline
- address sender (only this msg.sender can initiate the transaction to the delegate)

The signature must evaluate before the deadline, the counter must not be burned, and only the allowed sender is allowed to initiate the transaction. No execution data is verified. 

The signature types in in session mode are:
1. SessionExecution(uint128 counter,uint32 deadline,address sender,address outputContract) - limits to a single contract
2. ArbitrarySessionExecution(uint128 counter,uint32 deadline,address sender) - any contract (dangerous)
3. BurnSessionCounter(uint128 counter,address sender)

## Functions and return types

Each function in each mode has multiple kinds of interactions. 
See the interfaces to see all the function types available. There is repeat functionality that has:
- No return type to save gas. This will only revert on failure
- Takes only arguments as calldata to reduce gas costs on parsing
- Batch transaction variations

Also, the delegate has the ability to be called via the fallback function. This enables smaller calldata with custom parsing to save gas further.

# What could go wrong?
There are two major things that can go wrong:
1. A user's wallet is drained
- The EIP-712 validation failing open
- There is a missing authorization check
- No way to cancel a transaction
- The nonce being replayed
- A malicious transaction is signed
- Batch transactions only validate part of the batch in execution mode
- User is unable to recieve some tokens
2. A paymaster pays for a transaction that it doesn't want to 
- The delegate it interacts with is not the gas delegate
- The transaction steals eth from the pay master 
- The transaction griefs eth being expensive
- The gas station or delegate itself griefs the paymaster

# What are we doing about it? 

## User wallet protection
The following protections are in place: 
1. Signature validation done with solady that verifies only the user gave authorization
2. Negative tests to ensure authorization checks are implemented
3. A nonce/counter set up with burn functionality to prevent a transaction. A user can burn their nonces/counters directly without a paymaster
4. Each nonce will increment before use. If a user delegates to a new delegate, that delegate can overwrite the memory space and reset the nonce, but at that point that delegate could just steal all the funds anyway. 
5. A malicious transaction can be signed anyway even if the user is not using this delegate. An added risk is that a session metatransaction is signed with a long deadline, but is not used until the user deposits significant funds. This can be mitigated by burning the counter, but since the signature is not broadcasted the user would have to be aware
6. All transactions are validated in batch transactions are validated as part of the type hash
7. ERC-721 and ERC-1155 recievers are implemented. An eth reciever function is implemented.

## Paymaster protection
1. The gas station will verify the user is delegated to the right gas delegate. This can also be done off chain. The paymaster can interact with the delegate directly to save gas if if the paymaster trusts the delegate or does off-chain validation. 
2. The gas station does not allow any eth to be sent to it. If the paymaster has a policy to only interact with it, it will not send any eth
3. Off chain the paymaster has to parse the transaction and set gas limits. This cannot be purely protected on chain
4. The gas station and gas delegate are made to be gas efficient. Batch transactions have a hard limit of 20. 

# Outstanding questions/areas of focus for the auditors

1. Should this be compliant with EIP-7821 or EIP-1271? I don't think it has to, but I am open to hearing the other side. 
2. Should some session execution modes be "one time" to be used once? 
3. For approve then execute, does the approve logic make sense? This is custom to be certain it will work with USDT on mainnet https://github.com/tkhq/gas-station/blob/main/src/TKGasStation/TKGasDelegate.sol#L510-L525 instead of using SafeERC20 
4. There are a lot of repeat/slightly different inline assembly blocks. Are they all okay? Most of the reason they exist is to have extra-gas efficient modes that do not parse calldata, and interact with the bytes directly
5. I mixed up some areas where the contract that is interacted with is called "outputContract" or "to" - I should probably make this consistent
6. In the no-return areas, are there cases where the failure won't revert and just "fail open"? 
7. Are there ways to bypass the needed checks? Does each function have all the right needed checks?
8. Are there missing negative tests I should add? 
9. Is the fallback functionality something I should remove? 
10. How will this behave with native gas tokens on L2s that are not ethereum? Will it behave the same way? 
11. Any gas optimization suggestions? 