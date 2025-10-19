// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30;

/// @title Role-Based Access Control
/// @author lynett.eth
library LibRBAC {
    /// The ID of the default admin role with the ability to edit all other users' roles
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x0;

    /// @notice Emitted when a role is granted to a holder
    event RoleGranted(bytes32 indexed _role, address indexed _holder);
    /// @notice Emitted when a role is revoked from a holder
    event RoleRevoked(bytes32 indexed _role, address indexed _holder);
    /// @notice Emitted when a role admin is changed
    event RoleAdminChanged(
        bytes32 indexed role,
        bytes32 indexed prevAdmin,
        bytes32 indexed newAdmin
    );

    /// @notice Thrown when granting a role to an address which already holds it
    /// @param _role Role ID
    /// @param _receiver Invalid receiver address.
    error RoleHeld(bytes32 _role, address _receiver);

    /// @notice Thrown when revoking a role from an address which doesn't hold it
    /// @param _role Role ID
    /// @param _receiver Invalid receiver address.
    error RoleNotHeld(bytes32 _role, address _receiver);

    /// @notice Thrown when an account doesn't have a given role
    /// @param _role Role ID
    /// @param _receiver Invalid receiver address.
    error RoleRequired(bytes32 _role, address _receiver);

    /// @dev Storage position constant defined via keccak256 hash of diamond storage identifier.
    bytes32 constant STORAGE_POSITION = keccak256("compose.rbac");

    /// @custom:storage-location erc8042:compose.rbac
    /// @notice Storage layout for Role-Based Access Control
    struct RBACStorage {
        mapping(bytes32 role => mapping(address owner => bool has)) hasRole;
        mapping(bytes32 role => bytes32 admin) roleAdmin;
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

    function grantRole(bytes32 _role, address _holder) internal {
        RBACStorage storage s = getStorage();
        if (s.hasRole[_role][_holder]) revert RoleHeld(_role, _holder);
        s.hasRole[_role][_holder] = true;
    }

    function revokeRole(bytes32 _role, address _holder) internal {
        RBACStorage storage s = getStorage();
        if (!s.hasRole[_role][_holder]) revert RoleNotHeld(_role, _holder);
        s.hasRole[_role][_holder] = false;
    }

    function requireRole(bytes32 _role, address _holder) internal view {
        if (!getStorage().hasRole[_role][_holder])
            revert RoleRequired(_role, _holder);
    }

    function requireRole(bytes32 _role) internal view {
        if (!getStorage().hasRole[_role][msg.sender])
            revert RoleRequired(_role, msg.sender);
    }

    function requireRoleAdmin(bytes32 _role, address _holder) internal view {
        if (!hasRole(getRoleAdmin(_role), _holder))
            revert RoleRequired(_role, _holder);
    }

    function requireRoleAdmin(bytes32 _role) internal view {
        if (!hasRole(getRoleAdmin(_role), msg.sender))
            revert RoleRequired(_role, msg.sender);
    }

    function hasRole(
        bytes32 _role,
        address _holder
    ) internal view returns (bool) {
        return getStorage().hasRole[_role][_holder];
    }

    function getRoleAdmin(bytes32 _role) internal view returns (bytes32) {
        return getStorage().roleAdmin[_role];
    }

    function setRoleAdmin(bytes32 _role, bytes32 _admin) internal {
        RBACStorage storage s = getStorage();
        emit RoleAdminChanged(_role, s.roleAdmin[_role], _admin);
        s.roleAdmin[_role] = _admin;
    }
}
