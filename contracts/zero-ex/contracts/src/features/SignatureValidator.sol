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
import "../errors/LibSignatureRichErrors.sol";
import "../fixins/FixinCommon.sol";
import "../migrations/LibMigrate.sol";
import "./ISignatureValidator.sol";
import "./IFeature.sol";


/// @dev Feature for validating signatures.
contract SignatureValidator is
    IFeature,
    ISignatureValidator,
    FixinCommon
{
    using LibBytesV06 for bytes;
    using LibRichErrorsV06 for bytes;

    /// @dev Name of this feature.
    string public constant override FEATURE_NAME = "SignatureValidator";
    /// @dev Version of this feature.
    uint256 public immutable override FEATURE_VERSION = _encodeVersion(1, 0, 0);

    constructor() public FixinCommon() {
        // solhint-disable-next-line no-empty-blocks
    }

    /// @dev Initialize and register this feature.
    ///      Should be delegatecalled by `Migrate.migrate()`.
    /// @return success `LibMigrate.SUCCESS` on success.
    function migrate()
        external
        returns (bytes4 success)
    {
        _registerFeatureFunction(this.isValidHashSignature.selector);
        return LibMigrate.MIGRATE_SUCCESS;
    }

    function isValidHashSignature(
        bytes32 hash,
        address signer,
        bytes memory signature
    )
        public
        override
        view
        returns (bool isValid)
    {
        SignatureType signatureType = _readValidSignatureType(
            hash,
            signer,
            signature
        );

        // TODO: When we support non-hash signature types, assert that
        // `signatureType` is only `EIP712` or `EthSign` here.

        return _validateHashSignatureTypes(
            signatureType,
            hash,
            signer,
            signature
        );
    }

    /// Validates a hash-only signature type.
    function _validateHashSignatureTypes(
        SignatureType signatureType,
        bytes32 hash,
        address signerAddress,
        bytes memory signature
    )
        internal
        pure
        returns (bool isValid)
    {
        if (signatureType == SignatureType.Invalid) {
            // Always invalid signature.
            // Like Illegal, this is always implicitly available and therefore
            // offered explicitly. It can be implicitly created by providing
            // a correctly formatted but incorrect signature.
            if (signature.length != 1) {
                LibSignatureRichErrors.SignatureValidationError(
                    LibSignatureRichErrors.SignatureValidationErrorCodes.INVALID_LENGTH,
                    hash,
                    signerAddress,
                    signature
                ).rrevert();
            }
            isValid = false;
        } else if (signatureType == SignatureType.EIP712) {
            // Signature using EIP712
            if (signature.length != 66) {
                LibSignatureRichErrors.SignatureValidationError(
                    LibSignatureRichErrors.SignatureValidationErrorCodes.INVALID_LENGTH,
                    hash,
                    signerAddress,
                    signature
                ).rrevert();
            }
            uint8 v = uint8(signature[0]);
            bytes32 r = signature.readBytes32(1);
            bytes32 s = signature.readBytes32(33);
            address recovered = ecrecover(
                hash,
                v,
                r,
                s
            );
            isValid = signerAddress == recovered;
        } else if (signatureType == SignatureType.EthSign) {
            // Signed using `eth_sign`
            if (signature.length != 66) {
                LibSignatureRichErrors.SignatureValidationError(
                    LibSignatureRichErrors.SignatureValidationErrorCodes.INVALID_LENGTH,
                    hash,
                    signerAddress,
                    signature
                ).rrevert();
            }
            uint8 v = uint8(signature[0]);
            bytes32 r = signature.readBytes32(1);
            bytes32 s = signature.readBytes32(33);
            address recovered = ecrecover(
                keccak256(abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    hash
                )),
                v,
                r,
                s
            );
            isValid = signerAddress == recovered;
        } else {
            // This should never happen.
            revert('SignatureValidator/ILLEGAL_CODE_PATH');
        }
    }

    /// @dev Reads the `SignatureType` from the end of a signature and validates it.
    function _readValidSignatureType(
        bytes32 hash,
        address signerAddress,
        bytes memory signature
    )
        internal
        pure
        returns (SignatureType signatureType)
    {
        // Read the signatureType from the signature
        signatureType = _readSignatureType(
            hash,
            signerAddress,
            signature
        );

        // Disallow address zero because ecrecover() returns zero on failure.
        if (signerAddress == address(0)) {
            LibSignatureRichErrors.SignatureValidationError(
                LibSignatureRichErrors.SignatureValidationErrorCodes.INVALID_SIGNER,
                hash,
                signerAddress,
                signature
            ).rrevert();
        }

        // Ensure signature is supported
        if (uint8(signatureType) >= uint8(SignatureType.NSignatureTypes)) {
            LibSignatureRichErrors.SignatureValidationError(
                LibSignatureRichErrors.SignatureValidationErrorCodes.UNSUPPORTED,
                hash,
                signerAddress,
                signature
            ).rrevert();
        }

        // Always illegal signature.
        // This is always an implicit option since a signer can create a
        // signature array with invalid type or length. We may as well make
        // it an explicit option. This aids testing and analysis. It is
        // also the initialization value for the enum type.
        if (signatureType == SignatureType.Illegal) {
            LibSignatureRichErrors.SignatureValidationError(
                LibSignatureRichErrors.SignatureValidationErrorCodes.ILLEGAL,
                hash,
                signerAddress,
                signature
            ).rrevert();
        }
    }

    /// @dev Reads the `SignatureType` from a signature with minimal validation.
    function _readSignatureType(
        bytes32 hash,
        address signerAddress,
        bytes memory signature
    )
        internal
        pure
        returns (SignatureType)
    {
        if (signature.length == 0) {
            LibSignatureRichErrors.SignatureValidationError(
                LibSignatureRichErrors.SignatureValidationErrorCodes.INVALID_LENGTH,
                hash,
                signerAddress,
                signature
            ).rrevert();
        }
        return SignatureType(uint8(signature[signature.length - 1]));
    }
}
