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

import "@0x/contracts-utils/contracts/src/v06/errors/LibRichErrorsV06.sol";
import "@0x/contracts-utils/contracts/src/v06/LibBytesV06.sol";
import "../errors/LibMetaTransactionsRichErrors.sol";
import "../fixins/FixinCommon.sol";
import "../fixins/FixinEIP712.sol";
import "../migrations/LibMigrate.sol";
import "../storage/LibMetaTransactionsStorage.sol";
import "./IMetaTransactions.sol";
import "./ITransformERC20.sol";
import "./ISignatureValidator.sol";
import "./ITokenSpender.sol";
import "./IFeature.sol";


/// @dev MetaTransactions feature.
contract MetaTransactions is
    IFeature,
    IMetaTransactions,
    FixinCommon,
    FixinEIP712
{
    using LibBytesV06 for bytes;
    using LibRichErrorsV06 for bytes;

    /// @dev Name of this feature.
    string public constant override FEATURE_NAME = "MetaTransactions";
    /// @dev Version of this feature.
    uint256 public immutable override FEATURE_VERSION = _encodeVersion(1, 0, 0);
    /// @dev EIP712 typehash of the `MetaTransactionData` struct.
    bytes32 public immutable MTX_EIP712_TYPEHASH = keccak256(
        "MetaTransactionData("
            "address signer,"
            "address sender,"
            "uint256 minGasPrice,"
            "uint256 maxGasPrice,"
            "uint256 expirationTime,"
            "uint256 salt,"
            "bytes callData,"
            "uint256 value,"
            "IERC20TokenV06 feeToken,"
            "uint256 feeAmount"
        ")"
    );

    constructor(address zeroExAddress)
        public
        FixinCommon()
        FixinEIP712(zeroExAddress)
    {
        // solhint-disable-next-line no-empty-blocks
    }

    /// @dev Initialize and register this feature.
    ///      Should be delegatecalled by `Migrate.migrate()`.
    /// @return success `LibMigrate.SUCCESS` on success.
    function migrate()
        external
        returns (bytes4 success)
    {
        _registerFeatureFunction(this.executeMetaTransaction.selector);
        _registerFeatureFunction(this.executeMetaTransactions.selector);
        _registerFeatureFunction(this._executeMetaTransaction.selector);
        _registerFeatureFunction(this.getMetaTransactionExecutedBlock.selector);
        _registerFeatureFunction(this.getMetaTransactionHashExecutedBlock.selector);
        _registerFeatureFunction(this.getMetaTransactionHash.selector);
        return LibMigrate.MIGRATE_SUCCESS;
    }

    /// @dev Execute a single meta-transaction.
    function executeMetaTransaction(
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        public
        payable
        override
        returns (bytes memory returnData)
    {
        return _executeMetaTransactionPrivate(
            msg.sender,
            mtx,
            signature
        );
    }

    /// @dev Execute multiple meta-transactions.
    function executeMetaTransactions(
        MetaTransactionData[] memory mtxs,
        bytes[] memory signatures
    )
        public
        payable
        override
        returns (bytes[] memory returnDatas)
    {
        if (mtxs.length != signatures.length) {
            LibMetaTransactionsRichErrors.InvalidMetaTransactionsArrayLengthsError(
                mtxs.length,
                signatures.length
            ).rrevert();
        }
        returnDatas = new bytes[](mtxs.length);
        for (uint256 i = 0; i < mtxs.length; ++i) {
            returnDatas[i] = _executeMetaTransactionPrivate(
                msg.sender,
                mtxs[i],
                signatures[i]
            );
        }
    }

    /// @dev Execute a meta-transaction via `sender`. Privileged variant.
    ///      Only callable from within.
    function _executeMetaTransaction(
        address sender,
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        public
        payable
        override
        onlySelf
        returns (bytes memory returnData)
    {
        return _executeMetaTransactionPrivate(sender, mtx, signature);
    }

    /// @dev Get the block at which a meta-transaction has been executed.
    function getMetaTransactionExecutedBlock(MetaTransactionData memory mtx)
        public
        override
        view
        returns (uint256 blockNumber)
    {
        return getMetaTransactionHashExecutedBlock(getMetaTransactionHash(mtx));
    }

    /// @dev Get the block at which a meta-transaction hash has been executed.
    function getMetaTransactionHashExecutedBlock(bytes32 hash)
        public
        override
        view
        returns (uint256 blockNumber)
    {
        return LibMetaTransactionsStorage.getStorage().mtxHashToExecutedBlockNumber[hash];
    }

    /// @dev Get the hash of a meta-transaction.
    function getMetaTransactionHash(MetaTransactionData memory mtx)
        public
        override
        view
        returns (bytes32 mtxHash)
    {
        return _getEIP712Hash(keccak256(abi.encodePacked(
            MTX_EIP712_TYPEHASH,
            mtx.signer,
            mtx.sender,
            mtx.minGasPrice,
            mtx.maxGasPrice,
            mtx.expirationTime,
            mtx.salt,
            keccak256(mtx.callData),
            mtx.value,
            mtx.feeToken,
            mtx.feeAmount
        )));
    }

    /// @dev Execute a meta-transaction by `sender`. Privileged variant.
    ///      Only callable from within.
    function _executeMetaTransactionPrivate(
        address sender,
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        private
        returns (bytes memory returnData)
    {
        bytes32 hash = getMetaTransactionHash(mtx);
        _validateMetaTransaction(sender, hash, mtx, signature);

        // Mark the transaction executed.
        LibMetaTransactionsStorage.getStorage()
            .mtxHashToExecutedBlockNumber[hash] = block.number;

        // Execute the call based on the selector.
        bytes4 selector = mtx.callData.readBytes4(0);
        if (selector == ITransformERC20.transformERC20.selector) {
            returnData = _executeTransformERC20Call(hash, mtx);
        } else {
            LibMetaTransactionsRichErrors
                .UnsupportedMetaTransactionFunctionError(hash, selector)
                .rrevert();
        }
        // Pay the fee to the sender.
        if (mtx.feeAmount > 0) {
            ITokenSpender(address(this))._spendERC20Tokens(
                mtx.feeToken,
                mtx.signer, // From the signer.
                sender, // To the sender.
                mtx.feeAmount
            );
        }
        // HACK(dorothy-zbornak): Re-using `selector` here causes a stack too deep.
        emit MetaTransactionExecuted(
            hash,
            mtx.callData.readBytes4(0),
            mtx.signer,
            mtx.sender
        );
    }

    function _validateMetaTransaction(
        address sender,
        bytes32 hash,
        MetaTransactionData memory mtx,
        bytes memory signature
    )
        internal
        view
    {
        // Must be from the required sender, if set.
        if (mtx.sender != address(0) && mtx.sender != sender) {
            LibMetaTransactionsRichErrors
                .MetaTransactionWrongSenderError(
                    hash,
                    sender,
                    mtx.sender
                ).rrevert();
        }
        // Must not be expired.
        if (mtx.expirationTime <= block.timestamp) {
            LibMetaTransactionsRichErrors
                .MetaTransactionExpiredError(
                    hash,
                    block.timestamp,
                    mtx.expirationTime
                ).rrevert();
        }
        // Must have a valid gas price.
        if (mtx.minGasPrice > tx.gasprice || mtx.maxGasPrice < tx.gasprice) {
            LibMetaTransactionsRichErrors
                .MetaTransactionGasPriceError(
                    hash,
                    tx.gasprice,
                    mtx.minGasPrice,
                    mtx.maxGasPrice
                ).rrevert();
        }
        // Must have enough ETH.
        {
            uint256 bal = address(this).balance;
            if (mtx.value <= bal) {
                LibMetaTransactionsRichErrors
                    .MetaTransactionInsufficientEthError(
                        hash,
                        bal,
                        mtx.value
                    ).rrevert();
            }
        }
        // Must be signed by signer.
        if (!ISignatureValidator(address(this))
            .isValidHashSignature(hash, mtx.signer, signature))
        {
            LibMetaTransactionsRichErrors
                .MetaTransactionInvalidSignatureError(
                    hash,
                    signature
                ).rrevert();
        }
        // Transaction must not have been already executed.
        {
            uint256 executedBlockNumber = LibMetaTransactionsStorage
                .getStorage().mtxHashToExecutedBlockNumber[hash];
            if (executedBlockNumber != 0) {
                LibMetaTransactionsRichErrors
                    .MetaTransactionAlreadyExecutedError(
                        hash,
                        executedBlockNumber
                    ).rrevert();
            }
        }
    }

    function _executeTransformERC20Call(
        bytes32 hash,
        MetaTransactionData memory mtx
    )
        private
        returns (bytes memory returnData)
    {
        // Decode call args for `ITransformERC20.transformERC20()`
        (
            IERC20TokenV06 inputToken,
            IERC20TokenV06 outputToken,
            uint256 inputTokenAmount,
            uint256 minOutputTokenAmount,
            ITransformERC20.Transformation[] memory transformations
        ) = abi.decode(
            mtx.callData,
            (IERC20TokenV06, IERC20TokenV06, uint256, uint256, ITransformERC20.Transformation[])
        );
        // Call `ITransformERC20._transformERC20()` (internal variant).
        return _callSelf(
            hash,
            abi.encodeWithSelector(
                ITransformERC20._transformERC20.selector,
                keccak256(mtx.callData), // calldata hash is of original
                mtx.signer, // taker is mtx signer
                inputToken,
                outputToken,
                inputTokenAmount,
                minOutputTokenAmount,
                transformations
            ),
            mtx.value
        );
    }

    function _callSelf(bytes32 hash, bytes memory callData, uint256 value)
        private
        returns (bytes memory returnData)
    {
        bool success;
        (success, returnData) = address(this).call{value: value}(callData);
        if (!success) {
            LibMetaTransactionsRichErrors.MetaTransactionCallFailedError(
                hash,
                callData,
                returnData
            ).rrevert();
        }
    }
}
