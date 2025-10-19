// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30;

/// @title Role-Based Access Control Facet
/// @author lynett.eth
contract RBACFacet {
    /// @dev Storage position constant defined via keccak256 hash of diamond storage identifier.
    bytes32 constant STORAGE_POSITION = keccak256("compose.rbac");

    /// @custom:storage-location erc8042:compose.rbac
    /// @notice Storage layout for Role-Based Access Control
    struct RBACStorage {
        mapping(bytes32 role => mapping(address owner => bool has)) hasRole;
    }

    /// @notice Returns the RBAC storage struct from its predefined slot.
    /// @dev Uses inline assembly to access diamond storage location.
    /// @return s The storage reference for RBAC state variables.
    function getStorage() internal pure returns (RBACStorage storage s) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }

    function hasRole(
        bytes32 _role,
        address _holder
    ) external view returns (bool) {
        return getStorage().hasRole[_role][_holder];
    }
}
