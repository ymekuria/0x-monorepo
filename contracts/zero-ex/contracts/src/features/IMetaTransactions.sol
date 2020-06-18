/*

  Copyright 2020 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.6.5;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/v06/IERC20TokenV06.sol";


/// @dev Meta-transactions feature.
interface IMetaTransactions {

    /// @dev Describes an exchange proxy meta transaction.
    struct MetaTransactionData {
        // Signer of meta-transaction. On whose behalf to execute the MTX.
        address signer;
        // Required sender, or NULL for anyone.
        address sender;
        // Minimum gas price.
        uint256 minGasPrice;
        // Maximum gas price.
        uint256 maxGasPrice;
        // MTX is invalid after this time.
        uint256 expirationTime;
        // Nonce to make this MTX unique.
        uint256 salt;
        // Encoded call data to a function on the exchange proxy.
        bytes callData;
        // Amount of ETH to attach to the call.
        uint256 value;
        // ERC20 fee `signer` pays `sender`.
        IERC20TokenV06 feeToken;
        // ERC20 fee amount.
        uint256 feeAmount;
    }

    event MetaTransactionExecuted(
        bytes32 hash,
        bytes4 indexed selector,
        address signer,
        address sender
    );

    /// @dev Execute a single meta-transaction.
    function executeMetaTransaction(
        MetaTransactionData calldata mtx,
        bytes calldata signature
    )
        external
        payable
        returns (bytes memory returnData);

    /// @dev Execute multiple meta-transactions.
    function executeMetaTransactions(
        MetaTransactionData[] calldata mtxs,
        bytes[] calldata signatures
    )
        external
        payable
        returns (bytes[] memory returnDatas);

    /// @dev Execute a meta-transaction via `sender`. Privileged variant.
    ///      Only callable from within.
    function _executeMetaTransaction(
        address sender,
        MetaTransactionData calldata mtx,
        bytes calldata signature
    )
        external
        payable
        returns (bytes memory returnData);

    /// @dev Get the block at which a meta-transaction has been executed.
    function getMetaTransactionExecutedBlock(MetaTransactionData calldata mtx)
        external
        view
        returns (uint256 blockNumber);

    /// @dev Get the block at which a meta-transaction hash has been executed.
    function getMetaTransactionHashExecutedBlock(bytes32 mtxHash)
        external
        view
        returns (uint256 blockNumber);

    /// @dev Get the hash of a meta-transaction.
    function getMetaTransactionHash(MetaTransactionData calldata mtx)
        external
        view
        returns (bytes32 mtxHash);
}
