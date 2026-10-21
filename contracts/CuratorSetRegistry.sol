// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./CuratorSet.sol";

/// @title CuratorSetRegistry
/// @notice One curator set PER ORGANIZATION. Resolves an organization id to the
///         `CuratorSet` that governs its snapshots and distributions.
///
/// @dev WHY THIS EXISTS. Until 2026-08-30 a single `CuratorSet` governed the
///      whole chain: `PoSSRegistry` and `PoSSRewards` each received one address
///      in their constructor, with no setter, and neither `submitSnapshot` nor
///      `distribute` carried an organization id. Every hub therefore drove the
///      SAME contract. Measured that day: one organization's console removed
///      three curators at 09:44; an hour later a DIFFERENT organization could no
///      longer validate a signal — "signataire hors du CuratorSet on-chain" —
///      with nothing in its own logs to explain it. Dating the mutation took
///      `eth_call` at historical heights and a bisection on `getCuratorCount()`
///      down to block 3416.
///
///      An application-layer guard was written first and was not enough: it
///      makes one hub polite, it does not make the chain enforce anything. The
///      separation had to move on-chain, which is what this contract does.
///
/// @dev THE ADMIN IS THE FOUNDATION, and its power is deliberately bounded.
///      Assigning a curator set decides WHO may authorize an organization's
///      snapshots; it does not decide WHERE the money goes. The recipient list
///      stays bound to `payoutsHash`, fixed at anchoring under the previous
///      set's signatures, so reassigning a set after an anchor authorizes
///      nothing but the payouts already anchored. Reassignment is allowed on
///      purpose — an organization must be able to rotate a compromised set —
///      and the previous address is emitted so the change is legible on-chain.
///
/// @dev Admin transfer follows the same 2-step propose+accept pattern as
///      `CuratorSet`, for the same reason: an admin key must not be
///      transferable to an address that cannot accept it.
///
/// @dev No pause switch, consistent with `CuratorSet`. Emergency action is
///      `setCuratorSet` — explicit, audited by an event, and scoped to one
///      organization.
contract CuratorSetRegistry {
    /// @dev orgId is keccak256(bytes(slug)) — the slug already identifies an
    ///      organization everywhere else (PAW derivation, manifests, the
    ///      Foundation's PoR registry). It is an identifier, never a secret:
    ///      authority comes from the curator signatures, not from knowing it.
    mapping(bytes32 => address) private _curatorSetOf;
    uint256 public organizationCount;

    address public admin;
    address public pendingAdmin;

    event CuratorSetAssigned(bytes32 indexed orgId, address indexed curatorSet, address indexed previous);
    event AdminProposed(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminAccepted(address indexed previousAdmin, address indexed newAdmin);

    error NotPendingAdmin();
    error ZeroAddress();
    error UnknownOrganization(bytes32 orgId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CuratorSetRegistry: not admin");
        _;
    }

    constructor(address initialAdmin) {
        if (initialAdmin == address(0)) revert ZeroAddress();
        admin = initialAdmin;
        emit AdminAccepted(address(0), initialAdmin);
    }

    /// @notice Assign (or rotate) the curator set that governs `orgId`.
    /// @dev Reverts on a zero address rather than allowing an organization to be
    ///      silently un-assigned: an organization whose set resolves to zero
    ///      cannot anchor at all, and turning that into a one-word mistake would
    ///      make it an accidental denial of service.
    function setCuratorSet(bytes32 orgId, address curatorSetAddress) external onlyAdmin {
        require(orgId != bytes32(0), "CuratorSetRegistry: orgId=0");
        if (curatorSetAddress == address(0)) revert ZeroAddress();

        address previous = _curatorSetOf[orgId];
        if (previous == address(0)) organizationCount += 1;
        _curatorSetOf[orgId] = curatorSetAddress;
        emit CuratorSetAssigned(orgId, curatorSetAddress, previous);
    }

    /// @notice The curator set governing `orgId`, or address(0) if unassigned.
    function curatorSetOf(bytes32 orgId) external view returns (address) {
        return _curatorSetOf[orgId];
    }

    /// @notice Same, but reverting when unassigned — the form callers should use
    ///         when an absent set must stop the operation rather than be read as
    ///         "no curators, therefore no threshold to meet".
    function requireCuratorSet(bytes32 orgId) external view returns (CuratorSet) {
        address set = _curatorSetOf[orgId];
        if (set == address(0)) revert UnknownOrganization(orgId);
        return CuratorSet(set);
    }

    function isRegistered(bytes32 orgId) external view returns (bool) {
        return _curatorSetOf[orgId] != address(0);
    }

    function proposeAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminProposed(admin, newAdmin);
    }

    function acceptAdmin() external {
        address pa = pendingAdmin;
        if (pa == address(0) || msg.sender != pa) revert NotPendingAdmin();
        address previous = admin;
        admin = pa;
        pendingAdmin = address(0);
        emit AdminAccepted(previous, pa);
    }
}
