
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title Lode Protocol KYC
/// @notice Handles KYC verification and delegation using Merkle trees.
contract LodeProtocolKYC is Ownable2Step {

    mapping(address => address) public delegates; 
    mapping(address => bytes32) public merkleRoots;
    mapping(address => uint256) public nonce;

    // Custom Errors
    error InvalidInput(string reason);
    error InvalidSignature(string reason);
    error UnauthorizedAction(string reason); 
    error StateError(string reason);

    // Events
    event DelegateModified(address indexed user, address indexed delegate);
    event AddressVerified(address indexed user, bytes32 merkleRoot);
    event KYCRevoked(address indexed user);
    event NewCheck( address addr);

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Adds new addresses to the KYC system
    /// @param listOfAddresses List of addresses to verify
    /// @param rootAddress The root address authorizing the KYC
    /// @param merkleRoot Merkle root representing verified addresses
    /// @param rootAddressSignature Signature from the root address
    /// @param lodeProtocolSignature Signature from the Lode Protocol admin
    function verifyKYC(
        address[] calldata listOfAddresses,
        address rootAddress,
        bytes32 merkleRoot,
        bytes memory rootAddressSignature,
        bytes memory lodeProtocolSignature
    ) external {
        if (rootAddress == address(0)) revert InvalidInput("Root address cannot be zero");
        if (listOfAddresses.length == 0) revert InvalidInput("Address list cannot be empty");

        uint256 currentNonce = nonce[rootAddress];
        uint256 timestamp = block.timestamp;
        bytes32 commonHash = keccak256(
            abi.encodePacked(listOfAddresses, rootAddress, merkleRoot, currentNonce, timestamp, address(this), block.chainid, timestamp)
        );

        if (recoverSigner(commonHash, rootAddressSignature) != rootAddress) {
            revert InvalidSignature("Invalid root address signature");
        }

        if (recoverSigner(commonHash, lodeProtocolSignature) != owner()) {
            revert UnauthorizedAction("Invalid Lode Protocol admin signature");
        }

        nonce[rootAddress]++;

        for (uint256 i = 0; i < listOfAddresses.length; i++) {
            address user = listOfAddresses[i];
            if (delegates[user] != rootAddress && user != rootAddress) {
                revert UnauthorizedAction("Invalid delegation");
            }
            merkleRoots[user] = merkleRoot;
            emit AddressVerified(user, merkleRoot);
        }
    }

    /// @notice Modifies the delegate for a user
    /// @param delegate The address to set as delegate
    function modifyDelegate(address delegate) external {
        if (delegate == address(0)) revert InvalidInput("Delegate cannot be zero address");
        if (delegate == msg.sender) revert InvalidInput("Cannot delegate to self");
        delegates[msg.sender] = delegate;
        emit DelegateModified(msg.sender, delegate);
    }

    /// @notice Revokes the KYC for the caller
    function revokeKYC() external {
        if (merkleRoots[msg.sender] == bytes32(0)) revert StateError("No KYC set");
        merkleRoots[msg.sender] = bytes32(0);
        emit KYCRevoked(msg.sender);
    }

    /// @notice Recovers the signer of a hashed message
    /// @param hash The hash of the signed message
    /// @param signature The signature to verify
    /// @return The address of the signer
    function recoverSigner(bytes32 hash, bytes memory signature)
        public
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length != 65) revert InvalidSignature("Invalid signature length");

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) revert InvalidSignature("Invalid signature value");

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) {
            revert InvalidSignature("Invalid 's' parameter");
        }

        return
            ecrecover(
                keccak256(
                    abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
                ),
                v,
                r,
                s
       );
}
        function getDelegates(address user) public view returns (address){
            return delegates[user];


        }

}
