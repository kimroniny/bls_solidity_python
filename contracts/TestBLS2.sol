// SPDX-License-Identifier: LGPL 3.0
pragma solidity ^0.8.15;

import {BLS2} from "./BLS2.sol";

contract TestBLS2 {

    // function verifySingle(
    //     uint256[2] calldata signature,
    //     uint256[4] calldata pubkey,
    //     uint256[2] calldata message
    // ) external view returns (bool) {
    //     return BLS2.verifySingle(signature, pubkey, message);
    // }

    // function verifySingleGasCost(
    //     uint256[2] calldata signature,
    //     uint256[4] calldata pubkey,
    //     uint256[2] calldata message
    // ) external view returns (uint256) {
    //     uint256 g = gasleft();
    //     require(BLS2.verifySingle(signature, pubkey, message), "BLSTest: expect succesful verification");
    //     return g - gasleft();
    // }

    function hashToPoint(bytes calldata domain, bytes calldata data) external view returns (uint256[2] memory p) {
        return BLS2.hashToPoint(domain, data);
    }

    function hashToField(bytes calldata domain, bytes calldata data) external view returns (uint256[2] memory p) {
        return BLS2.hashToField(domain, data);
    }

    function expandMsgTo96(bytes calldata domain, bytes calldata data) external view returns (bytes memory) {
        return BLS2.expandMsgTo96(domain, data);
    }

}
