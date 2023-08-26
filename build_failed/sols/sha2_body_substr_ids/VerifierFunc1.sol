// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "../VerifierFuncAbst.sol";

contract VerifierFunc1 is VerifierFuncAbst {
    function verifyPartial(
        uint256[] memory pubInputs,
        bytes memory proof,
        bool success,
        bytes memory _transcript
    ) public view override returns (bool, bytes memory) {
        bytes32[1323] memory transcript;
        // require(_transcript.length == 1323, "transcript length is not 1323");
        if (_transcript.length != 0) {
            transcript = abi.decode(_transcript, (bytes32[1323]));
        }
        // for(uint i=0; i<_transcript.length; i++) {
        //     transcript[i] = _transcript[i];
        // }
        assembly {
            {
                let
                    f_p
                := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                let
                    f_q
                := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
                function validate_ec_point(x, y) -> valid {
                    {
                        let x_lt_p := lt(
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let y_lt_p := lt(
                            y,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        valid := and(x_lt_p, y_lt_p)
                    }
                    {
                        let x_is_zero := eq(x, 0)
                        let y_is_zero := eq(y, 0)
                        let x_or_y_is_zero := or(x_is_zero, y_is_zero)
                        let x_and_y_is_not_zero := not(x_or_y_is_zero)
                        valid := and(x_and_y_is_not_zero, valid)
                    }
                    {
                        let y_square := mulmod(
                            y,
                            y,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_square := mulmod(
                            x,
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_cube := mulmod(
                            x_square,
                            x,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let x_cube_plus_3 := addmod(
                            x_cube,
                            3,
                            0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
                        )
                        let y_square_eq_x_cube_plus_3 := eq(
                            x_cube_plus_3,
                            y_square
                        )
                        valid := and(y_square_eq_x_cube_plus_3, valid)
                    }
                }
                mstore(add(transcript, 0x4ba0), 32)
                mstore(add(transcript, 0x4bc0), 32)
                mstore(add(transcript, 0x4be0), 32)
                mstore(add(transcript, 0x4c00), mload(add(transcript, 0x4b60)))
                mstore(
                    add(transcript, 0x4c20),
                    21888242871839275222246405745257275088548364400416034343698204186575808495615
                )
                mstore(
                    add(transcript, 0x4c40),
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x5,
                            add(transcript, 0x4ba0),
                            0xc0,
                            add(transcript, 0x4b80),
                            0x20
                        ),
                        1
                    ),
                    success
                )
                {
                    let inv := mload(add(transcript, 0x4b80))
                    let v
                    v := mload(add(transcript, 0x4980))
                    mstore(
                        add(transcript, 0x4980),
                        mulmod(mload(add(transcript, 0x4b40)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4960))
                    mstore(
                        add(transcript, 0x4960),
                        mulmod(mload(add(transcript, 0x4b20)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4940))
                    mstore(
                        add(transcript, 0x4940),
                        mulmod(mload(add(transcript, 0x4b00)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4800))
                    mstore(
                        add(transcript, 0x4800),
                        mulmod(mload(add(transcript, 0x4ae0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4920))
                    mstore(
                        add(transcript, 0x4920),
                        mulmod(mload(add(transcript, 0x4ac0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4900))
                    mstore(
                        add(transcript, 0x4900),
                        mulmod(mload(add(transcript, 0x4aa0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x48e0))
                    mstore(
                        add(transcript, 0x48e0),
                        mulmod(mload(add(transcript, 0x4a80)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x48c0))
                    mstore(
                        add(transcript, 0x48c0),
                        mulmod(mload(add(transcript, 0x4a60)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x48a0))
                    mstore(
                        add(transcript, 0x48a0),
                        mulmod(mload(add(transcript, 0x4a40)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4880))
                    mstore(
                        add(transcript, 0x4880),
                        mulmod(mload(add(transcript, 0x4a20)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x47e0))
                    mstore(
                        add(transcript, 0x47e0),
                        mulmod(mload(add(transcript, 0x4a00)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4860))
                    mstore(
                        add(transcript, 0x4860),
                        mulmod(mload(add(transcript, 0x49e0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x47c0))
                    mstore(
                        add(transcript, 0x47c0),
                        mulmod(mload(add(transcript, 0x49c0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x47a0))
                    mstore(
                        add(transcript, 0x47a0),
                        mulmod(mload(add(transcript, 0x49a0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4780))
                    mstore(
                        add(transcript, 0x4780),
                        mulmod(mload(add(transcript, 0x4760)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    mstore(add(transcript, 0x4760), inv)
                }
                {
                    let result := mload(add(transcript, 0x4760))
                    result := addmod(
                        mload(add(transcript, 0x4780)),
                        result,
                        f_q
                    )
                    result := addmod(
                        mload(add(transcript, 0x47a0)),
                        result,
                        f_q
                    )
                    result := addmod(
                        mload(add(transcript, 0x47c0)),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4c60), result)
                }
                mstore(
                    add(transcript, 0x4c80),
                    mulmod(
                        mload(add(transcript, 0x4840)),
                        mload(add(transcript, 0x47e0)),
                        f_q
                    )
                )
                {
                    let result := mload(add(transcript, 0x4860))
                    mstore(add(transcript, 0x4ca0), result)
                }
                mstore(
                    add(transcript, 0x4cc0),
                    mulmod(
                        mload(add(transcript, 0x4840)),
                        mload(add(transcript, 0x48e0)),
                        f_q
                    )
                )
                {
                    let result := mload(add(transcript, 0x4880))
                    result := addmod(
                        mload(add(transcript, 0x48a0)),
                        result,
                        f_q
                    )
                    result := addmod(
                        mload(add(transcript, 0x48c0)),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4ce0), result)
                }
                mstore(
                    add(transcript, 0x4d00),
                    mulmod(
                        mload(add(transcript, 0x4840)),
                        mload(add(transcript, 0x4800)),
                        f_q
                    )
                )
                {
                    let result := mload(add(transcript, 0x4900))
                    result := addmod(
                        mload(add(transcript, 0x4920)),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4d20), result)
                }
                mstore(
                    add(transcript, 0x4d40),
                    mulmod(
                        mload(add(transcript, 0x4840)),
                        mload(add(transcript, 0x4980)),
                        f_q
                    )
                )
                {
                    let result := mload(add(transcript, 0x4940))
                    result := addmod(
                        mload(add(transcript, 0x4960)),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x4d60), result)
                }
                {
                    let prod := mload(add(transcript, 0x4c60))
                    prod := mulmod(mload(add(transcript, 0x4ca0)), prod, f_q)
                    mstore(add(transcript, 0x4d80), prod)
                    prod := mulmod(mload(add(transcript, 0x4ce0)), prod, f_q)
                    mstore(add(transcript, 0x4da0), prod)
                    prod := mulmod(mload(add(transcript, 0x4d20)), prod, f_q)
                    mstore(add(transcript, 0x4dc0), prod)
                    prod := mulmod(mload(add(transcript, 0x4d60)), prod, f_q)
                    mstore(add(transcript, 0x4de0), prod)
                }
                mstore(add(transcript, 0x4e20), 32)
                mstore(add(transcript, 0x4e40), 32)
                mstore(add(transcript, 0x4e60), 32)
                mstore(add(transcript, 0x4e80), mload(add(transcript, 0x4de0)))
                mstore(
                    add(transcript, 0x4ea0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495615
                )
                mstore(
                    add(transcript, 0x4ec0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
                )
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x5,
                            add(transcript, 0x4e20),
                            0xc0,
                            add(transcript, 0x4e00),
                            0x20
                        ),
                        1
                    ),
                    success
                )
                {
                    let inv := mload(add(transcript, 0x4e00))
                    let v
                    v := mload(add(transcript, 0x4d60))
                    mstore(
                        add(transcript, 0x4d60),
                        mulmod(mload(add(transcript, 0x4dc0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4d20))
                    mstore(
                        add(transcript, 0x4d20),
                        mulmod(mload(add(transcript, 0x4da0)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4ce0))
                    mstore(
                        add(transcript, 0x4ce0),
                        mulmod(mload(add(transcript, 0x4d80)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    v := mload(add(transcript, 0x4ca0))
                    mstore(
                        add(transcript, 0x4ca0),
                        mulmod(mload(add(transcript, 0x4c60)), inv, f_q)
                    )
                    inv := mulmod(v, inv, f_q)
                    mstore(add(transcript, 0x4c60), inv)
                }
                mstore(
                    add(transcript, 0x4ee0),
                    mulmod(
                        mload(add(transcript, 0x4c80)),
                        mload(add(transcript, 0x4ca0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4f00),
                    mulmod(
                        mload(add(transcript, 0x4cc0)),
                        mload(add(transcript, 0x4ce0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4f20),
                    mulmod(
                        mload(add(transcript, 0x4d00)),
                        mload(add(transcript, 0x4d20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4f40),
                    mulmod(
                        mload(add(transcript, 0x4d40)),
                        mload(add(transcript, 0x4d60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4f60),
                    mulmod(
                        mload(add(transcript, 0x1460)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4f80),
                    mulmod(
                        mload(add(transcript, 0x4f60)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4fa0),
                    mulmod(
                        mload(add(transcript, 0x4f80)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4fc0),
                    mulmod(
                        mload(add(transcript, 0x4fa0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x4fe0),
                    mulmod(
                        mload(add(transcript, 0x4fc0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5000),
                    mulmod(
                        mload(add(transcript, 0x4fe0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5020),
                    mulmod(
                        mload(add(transcript, 0x5000)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5040),
                    mulmod(
                        mload(add(transcript, 0x5020)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5060),
                    mulmod(
                        mload(add(transcript, 0x5040)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5080),
                    mulmod(
                        mload(add(transcript, 0x5060)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x50a0),
                    mulmod(
                        mload(add(transcript, 0x5080)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x50c0),
                    mulmod(
                        mload(add(transcript, 0x50a0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x50e0),
                    mulmod(
                        mload(add(transcript, 0x50c0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5100),
                    mulmod(
                        mload(add(transcript, 0x50e0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5120),
                    mulmod(
                        mload(add(transcript, 0x5100)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5140),
                    mulmod(
                        mload(add(transcript, 0x5120)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5160),
                    mulmod(
                        mload(add(transcript, 0x5140)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5180),
                    mulmod(
                        mload(add(transcript, 0x5160)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x51a0),
                    mulmod(
                        mload(add(transcript, 0x5180)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x51c0),
                    mulmod(
                        mload(add(transcript, 0x51a0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x51e0),
                    mulmod(
                        mload(add(transcript, 0x51c0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5200),
                    mulmod(
                        mload(add(transcript, 0x51e0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5220),
                    mulmod(
                        mload(add(transcript, 0x5200)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5240),
                    mulmod(
                        mload(add(transcript, 0x5220)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5260),
                    mulmod(
                        mload(add(transcript, 0x5240)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5280),
                    mulmod(
                        mload(add(transcript, 0x5260)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x52a0),
                    mulmod(
                        mload(add(transcript, 0x5280)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x52c0),
                    mulmod(
                        mload(add(transcript, 0x14c0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x52e0),
                    mulmod(
                        mload(add(transcript, 0x52c0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5300),
                    mulmod(
                        mload(add(transcript, 0x52e0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5320),
                    mulmod(
                        mload(add(transcript, 0x5300)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x960)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x980)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x9a0)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x9c0)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x5340), result)
                }
                mstore(
                    add(transcript, 0x5360),
                    mulmod(
                        mload(add(transcript, 0x5340)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5380),
                    mulmod(sub(f_q, mload(add(transcript, 0x5360))), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x9e0)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xa00)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xa20)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xa40)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x53a0), result)
                }
                mstore(
                    add(transcript, 0x53c0),
                    mulmod(
                        mload(add(transcript, 0x53a0)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x53e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x53c0))),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5400),
                    mulmod(1, mload(add(transcript, 0x1460)), f_q)
                )
                mstore(
                    add(transcript, 0x5420),
                    addmod(
                        mload(add(transcript, 0x5380)),
                        mload(add(transcript, 0x53e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xa60)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xa80)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xaa0)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xac0)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x5440), result)
                }
                mstore(
                    add(transcript, 0x5460),
                    mulmod(
                        mload(add(transcript, 0x5440)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5480),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5460))),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x54a0),
                    mulmod(1, mload(add(transcript, 0x4f60)), f_q)
                )
                mstore(
                    add(transcript, 0x54c0),
                    addmod(
                        mload(add(transcript, 0x5420)),
                        mload(add(transcript, 0x5480)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xae0)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xb00)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xb20)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xb40)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x54e0), result)
                }
                mstore(
                    add(transcript, 0x5500),
                    mulmod(
                        mload(add(transcript, 0x54e0)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5520),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5500))),
                        mload(add(transcript, 0x4f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5540),
                    mulmod(1, mload(add(transcript, 0x4f80)), f_q)
                )
                mstore(
                    add(transcript, 0x5560),
                    addmod(
                        mload(add(transcript, 0x54c0)),
                        mload(add(transcript, 0x5520)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xb60)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xb80)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xba0)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xbc0)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x5580), result)
                }
                mstore(
                    add(transcript, 0x55a0),
                    mulmod(
                        mload(add(transcript, 0x5580)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x55c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x55a0))),
                        mload(add(transcript, 0x4fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x55e0),
                    mulmod(1, mload(add(transcript, 0x4fa0)), f_q)
                )
                mstore(
                    add(transcript, 0x5600),
                    addmod(
                        mload(add(transcript, 0x5560)),
                        mload(add(transcript, 0x55c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xbe0)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xc00)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xc20)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xc40)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x5620), result)
                }
                mstore(
                    add(transcript, 0x5640),
                    mulmod(
                        mload(add(transcript, 0x5620)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5660),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5640))),
                        mload(add(transcript, 0x4fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5680),
                    mulmod(1, mload(add(transcript, 0x4fc0)), f_q)
                )
                mstore(
                    add(transcript, 0x56a0),
                    addmod(
                        mload(add(transcript, 0x5600)),
                        mload(add(transcript, 0x5660)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xc60)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xc80)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xca0)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xcc0)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x56c0), result)
                }
                mstore(
                    add(transcript, 0x56e0),
                    mulmod(
                        mload(add(transcript, 0x56c0)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5700),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x56e0))),
                        mload(add(transcript, 0x4fe0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5720),
                    mulmod(1, mload(add(transcript, 0x4fe0)), f_q)
                )
                mstore(
                    add(transcript, 0x5740),
                    addmod(
                        mload(add(transcript, 0x56a0)),
                        mload(add(transcript, 0x5700)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xce0)),
                        mload(add(transcript, 0x4760)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xd00)),
                            mload(add(transcript, 0x4780)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xd20)),
                            mload(add(transcript, 0x47a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0xd40)),
                            mload(add(transcript, 0x47c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x5760), result)
                }
                mstore(
                    add(transcript, 0x5780),
                    mulmod(
                        mload(add(transcript, 0x5760)),
                        mload(add(transcript, 0x4c60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x57a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5780))),
                        mload(add(transcript, 0x5000)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x57c0),
                    mulmod(1, mload(add(transcript, 0x5000)), f_q)
                )
                mstore(
                    add(transcript, 0x57e0),
                    addmod(
                        mload(add(transcript, 0x5740)),
                        mload(add(transcript, 0x57a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5800),
                    mulmod(mload(add(transcript, 0x57e0)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5820),
                    mulmod(mload(add(transcript, 0x5400)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5840),
                    mulmod(mload(add(transcript, 0x54a0)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5860),
                    mulmod(mload(add(transcript, 0x5540)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5880),
                    mulmod(mload(add(transcript, 0x55e0)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x58a0),
                    mulmod(mload(add(transcript, 0x5680)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x58c0),
                    mulmod(mload(add(transcript, 0x5720)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x58e0),
                    mulmod(mload(add(transcript, 0x57c0)), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5900),
                    mulmod(1, mload(add(transcript, 0x4c80)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xd60)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5920), result)
                }
                mstore(
                    add(transcript, 0x5940),
                    mulmod(
                        mload(add(transcript, 0x5920)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5960),
                    mulmod(sub(f_q, mload(add(transcript, 0x5940))), 1, f_q)
                )
                mstore(
                    add(transcript, 0x5980),
                    mulmod(mload(add(transcript, 0x5900)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xd80)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x59a0), result)
                }
                mstore(
                    add(transcript, 0x59c0),
                    mulmod(
                        mload(add(transcript, 0x59a0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x59e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x59c0))),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5a00),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5a20),
                    addmod(
                        mload(add(transcript, 0x5960)),
                        mload(add(transcript, 0x59e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xda0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5a40), result)
                }
                mstore(
                    add(transcript, 0x5a60),
                    mulmod(
                        mload(add(transcript, 0x5a40)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5a80),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5a60))),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5aa0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5ac0),
                    addmod(
                        mload(add(transcript, 0x5a20)),
                        mload(add(transcript, 0x5a80)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1380)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5ae0), result)
                }
                mstore(
                    add(transcript, 0x5b00),
                    mulmod(
                        mload(add(transcript, 0x5ae0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5b20),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5b00))),
                        mload(add(transcript, 0x4f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5b40),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x4f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5b60),
                    addmod(
                        mload(add(transcript, 0x5ac0)),
                        mload(add(transcript, 0x5b20)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1420)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5b80), result)
                }
                mstore(
                    add(transcript, 0x5ba0),
                    mulmod(
                        mload(add(transcript, 0x5b80)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5bc0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5ba0))),
                        mload(add(transcript, 0x4fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5be0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x4fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5c00),
                    addmod(
                        mload(add(transcript, 0x5b60)),
                        mload(add(transcript, 0x5bc0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xdc0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5c20), result)
                }
                mstore(
                    add(transcript, 0x5c40),
                    mulmod(
                        mload(add(transcript, 0x5c20)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5c60),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5c40))),
                        mload(add(transcript, 0x4fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5c80),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x4fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5ca0),
                    addmod(
                        mload(add(transcript, 0x5c00)),
                        mload(add(transcript, 0x5c60)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xde0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5cc0), result)
                }
                mstore(
                    add(transcript, 0x5ce0),
                    mulmod(
                        mload(add(transcript, 0x5cc0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5d00),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5ce0))),
                        mload(add(transcript, 0x4fe0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5d20),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x4fe0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5d40),
                    addmod(
                        mload(add(transcript, 0x5ca0)),
                        mload(add(transcript, 0x5d00)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xe00)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5d60), result)
                }
                mstore(
                    add(transcript, 0x5d80),
                    mulmod(
                        mload(add(transcript, 0x5d60)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5da0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5d80))),
                        mload(add(transcript, 0x5000)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5dc0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5000)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5de0),
                    addmod(
                        mload(add(transcript, 0x5d40)),
                        mload(add(transcript, 0x5da0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5e00),
                    addmod(
                        mload(add(transcript, 0x5d20)),
                        mload(add(transcript, 0x5dc0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xe20)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5e20), result)
                }
                mstore(
                    add(transcript, 0x5e40),
                    mulmod(
                        mload(add(transcript, 0x5e20)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5e60),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5e40))),
                        mload(add(transcript, 0x5020)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5e80),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5020)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5ea0),
                    addmod(
                        mload(add(transcript, 0x5de0)),
                        mload(add(transcript, 0x5e60)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xe40)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5ec0), result)
                }
                mstore(
                    add(transcript, 0x5ee0),
                    mulmod(
                        mload(add(transcript, 0x5ec0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5f00),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5ee0))),
                        mload(add(transcript, 0x5040)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5f20),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5040)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5f40),
                    addmod(
                        mload(add(transcript, 0x5ea0)),
                        mload(add(transcript, 0x5f00)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xe60)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x5f60), result)
                }
                mstore(
                    add(transcript, 0x5f80),
                    mulmod(
                        mload(add(transcript, 0x5f60)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5fa0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x5f80))),
                        mload(add(transcript, 0x5060)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5fc0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5060)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x5fe0),
                    addmod(
                        mload(add(transcript, 0x5f40)),
                        mload(add(transcript, 0x5fa0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xe80)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6000), result)
                }
                mstore(
                    add(transcript, 0x6020),
                    mulmod(
                        mload(add(transcript, 0x6000)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6040),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6020))),
                        mload(add(transcript, 0x5080)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6060),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5080)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6080),
                    addmod(
                        mload(add(transcript, 0x5fe0)),
                        mload(add(transcript, 0x6040)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xea0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x60a0), result)
                }
                mstore(
                    add(transcript, 0x60c0),
                    mulmod(
                        mload(add(transcript, 0x60a0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x60e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x60c0))),
                        mload(add(transcript, 0x50a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6100),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x50a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6120),
                    addmod(
                        mload(add(transcript, 0x6080)),
                        mload(add(transcript, 0x60e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xee0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6140), result)
                }
                mstore(
                    add(transcript, 0x6160),
                    mulmod(
                        mload(add(transcript, 0x6140)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6180),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6160))),
                        mload(add(transcript, 0x50c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x61a0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x50c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x61c0),
                    addmod(
                        mload(add(transcript, 0x6120)),
                        mload(add(transcript, 0x6180)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xf00)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x61e0), result)
                }
                mstore(
                    add(transcript, 0x6200),
                    mulmod(
                        mload(add(transcript, 0x61e0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6220),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6200))),
                        mload(add(transcript, 0x50e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6240),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x50e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6260),
                    addmod(
                        mload(add(transcript, 0x61c0)),
                        mload(add(transcript, 0x6220)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xf20)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6280), result)
                }
                mstore(
                    add(transcript, 0x62a0),
                    mulmod(
                        mload(add(transcript, 0x6280)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x62c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x62a0))),
                        mload(add(transcript, 0x5100)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x62e0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5100)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6300),
                    addmod(
                        mload(add(transcript, 0x6260)),
                        mload(add(transcript, 0x62c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xf40)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6320), result)
                }
                mstore(
                    add(transcript, 0x6340),
                    mulmod(
                        mload(add(transcript, 0x6320)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6360),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6340))),
                        mload(add(transcript, 0x5120)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6380),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5120)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x63a0),
                    addmod(
                        mload(add(transcript, 0x6300)),
                        mload(add(transcript, 0x6360)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xf60)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x63c0), result)
                }
                mstore(
                    add(transcript, 0x63e0),
                    mulmod(
                        mload(add(transcript, 0x63c0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6400),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x63e0))),
                        mload(add(transcript, 0x5140)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6420),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5140)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6440),
                    addmod(
                        mload(add(transcript, 0x63a0)),
                        mload(add(transcript, 0x6400)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xf80)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6460), result)
                }
                mstore(
                    add(transcript, 0x6480),
                    mulmod(
                        mload(add(transcript, 0x6460)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x64a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6480))),
                        mload(add(transcript, 0x5160)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x64c0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5160)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x64e0),
                    addmod(
                        mload(add(transcript, 0x6440)),
                        mload(add(transcript, 0x64a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xfa0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6500), result)
                }
                mstore(
                    add(transcript, 0x6520),
                    mulmod(
                        mload(add(transcript, 0x6500)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6540),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6520))),
                        mload(add(transcript, 0x5180)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6560),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5180)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6580),
                    addmod(
                        mload(add(transcript, 0x64e0)),
                        mload(add(transcript, 0x6540)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xfc0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x65a0), result)
                }
                mstore(
                    add(transcript, 0x65c0),
                    mulmod(
                        mload(add(transcript, 0x65a0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x65e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x65c0))),
                        mload(add(transcript, 0x51a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6600),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x51a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6620),
                    addmod(
                        mload(add(transcript, 0x6580)),
                        mload(add(transcript, 0x65e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xfe0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6640), result)
                }
                mstore(
                    add(transcript, 0x6660),
                    mulmod(
                        mload(add(transcript, 0x6640)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6680),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6660))),
                        mload(add(transcript, 0x51c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x66a0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x51c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x66c0),
                    addmod(
                        mload(add(transcript, 0x6620)),
                        mload(add(transcript, 0x6680)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1000)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x66e0), result)
                }
                mstore(
                    add(transcript, 0x6700),
                    mulmod(
                        mload(add(transcript, 0x66e0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6720),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6700))),
                        mload(add(transcript, 0x51e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6740),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x51e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6760),
                    addmod(
                        mload(add(transcript, 0x66c0)),
                        mload(add(transcript, 0x6720)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1020)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6780), result)
                }
                mstore(
                    add(transcript, 0x67a0),
                    mulmod(
                        mload(add(transcript, 0x6780)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x67c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x67a0))),
                        mload(add(transcript, 0x5200)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x67e0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5200)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6800),
                    addmod(
                        mload(add(transcript, 0x6760)),
                        mload(add(transcript, 0x67c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1040)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6820), result)
                }
                mstore(
                    add(transcript, 0x6840),
                    mulmod(
                        mload(add(transcript, 0x6820)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6860),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6840))),
                        mload(add(transcript, 0x5220)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6880),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5220)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x68a0),
                    addmod(
                        mload(add(transcript, 0x6800)),
                        mload(add(transcript, 0x6860)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1060)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x68c0), result)
                }
                mstore(
                    add(transcript, 0x68e0),
                    mulmod(
                        mload(add(transcript, 0x68c0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6900),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x68e0))),
                        mload(add(transcript, 0x5240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6920),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5240)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6940),
                    addmod(
                        mload(add(transcript, 0x68a0)),
                        mload(add(transcript, 0x6900)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6960),
                    mulmod(
                        mload(add(transcript, 0x4560)),
                        mload(add(transcript, 0x4c80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6980),
                    mulmod(
                        mload(add(transcript, 0x4580)),
                        mload(add(transcript, 0x4c80)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x45a0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x69a0), result)
                }
                mstore(
                    add(transcript, 0x69c0),
                    mulmod(
                        mload(add(transcript, 0x69a0)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x69e0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x69c0))),
                        mload(add(transcript, 0x5260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6a00),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6a20),
                    mulmod(
                        mload(add(transcript, 0x6960)),
                        mload(add(transcript, 0x5260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6a40),
                    mulmod(
                        mload(add(transcript, 0x6980)),
                        mload(add(transcript, 0x5260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6a60),
                    addmod(
                        mload(add(transcript, 0x6940)),
                        mload(add(transcript, 0x69e0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0xec0)),
                        mload(add(transcript, 0x4860)),
                        f_q
                    )
                    mstore(add(transcript, 0x6a80), result)
                }
                mstore(
                    add(transcript, 0x6aa0),
                    mulmod(
                        mload(add(transcript, 0x6a80)),
                        mload(add(transcript, 0x4ee0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ac0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6aa0))),
                        mload(add(transcript, 0x5280)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ae0),
                    mulmod(
                        mload(add(transcript, 0x5900)),
                        mload(add(transcript, 0x5280)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6b00),
                    addmod(
                        mload(add(transcript, 0x6a60)),
                        mload(add(transcript, 0x6ac0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6b20),
                    mulmod(
                        mload(add(transcript, 0x6b00)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6b40),
                    mulmod(
                        mload(add(transcript, 0x5980)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6b60),
                    mulmod(
                        mload(add(transcript, 0x5a00)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6b80),
                    mulmod(
                        mload(add(transcript, 0x5aa0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ba0),
                    mulmod(
                        mload(add(transcript, 0x5b40)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6bc0),
                    mulmod(
                        mload(add(transcript, 0x5be0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6be0),
                    mulmod(
                        mload(add(transcript, 0x5c80)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6c00),
                    mulmod(
                        mload(add(transcript, 0x5e00)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6c20),
                    mulmod(
                        mload(add(transcript, 0x5e80)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6c40),
                    mulmod(
                        mload(add(transcript, 0x5f20)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6c60),
                    mulmod(
                        mload(add(transcript, 0x5fc0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6c80),
                    mulmod(
                        mload(add(transcript, 0x6060)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ca0),
                    mulmod(
                        mload(add(transcript, 0x6100)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6cc0),
                    mulmod(
                        mload(add(transcript, 0x61a0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ce0),
                    mulmod(
                        mload(add(transcript, 0x6240)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6d00),
                    mulmod(
                        mload(add(transcript, 0x62e0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6d20),
                    mulmod(
                        mload(add(transcript, 0x6380)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6d40),
                    mulmod(
                        mload(add(transcript, 0x6420)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6d60),
                    mulmod(
                        mload(add(transcript, 0x64c0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6d80),
                    mulmod(
                        mload(add(transcript, 0x6560)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6da0),
                    mulmod(
                        mload(add(transcript, 0x6600)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6dc0),
                    mulmod(
                        mload(add(transcript, 0x66a0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6de0),
                    mulmod(
                        mload(add(transcript, 0x6740)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6e00),
                    mulmod(
                        mload(add(transcript, 0x67e0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6e20),
                    mulmod(
                        mload(add(transcript, 0x6880)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6e40),
                    mulmod(
                        mload(add(transcript, 0x6920)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6e60),
                    mulmod(
                        mload(add(transcript, 0x6a00)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6e80),
                    mulmod(
                        mload(add(transcript, 0x6a20)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ea0),
                    mulmod(
                        mload(add(transcript, 0x6a40)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ec0),
                    mulmod(
                        mload(add(transcript, 0x6ae0)),
                        mload(add(transcript, 0x14c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6ee0),
                    addmod(
                        mload(add(transcript, 0x5800)),
                        mload(add(transcript, 0x6b20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6f00),
                    mulmod(1, mload(add(transcript, 0x4cc0)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1080)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x10a0)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x10c0)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x6f20), result)
                }
                mstore(
                    add(transcript, 0x6f40),
                    mulmod(
                        mload(add(transcript, 0x6f20)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6f60),
                    mulmod(sub(f_q, mload(add(transcript, 0x6f40))), 1, f_q)
                )
                mstore(
                    add(transcript, 0x6f80),
                    mulmod(mload(add(transcript, 0x6f00)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x10e0)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1100)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1120)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x6fa0), result)
                }
                mstore(
                    add(transcript, 0x6fc0),
                    mulmod(
                        mload(add(transcript, 0x6fa0)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x6fe0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x6fc0))),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7000),
                    mulmod(
                        mload(add(transcript, 0x6f00)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7020),
                    addmod(
                        mload(add(transcript, 0x6f60)),
                        mload(add(transcript, 0x6fe0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1140)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1160)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1180)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7040), result)
                }
                mstore(
                    add(transcript, 0x7060),
                    mulmod(
                        mload(add(transcript, 0x7040)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7080),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7060))),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x70a0),
                    mulmod(
                        mload(add(transcript, 0x6f00)),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x70c0),
                    addmod(
                        mload(add(transcript, 0x7020)),
                        mload(add(transcript, 0x7080)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x11a0)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x11c0)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x11e0)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x70e0), result)
                }
                mstore(
                    add(transcript, 0x7100),
                    mulmod(
                        mload(add(transcript, 0x70e0)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7120),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7100))),
                        mload(add(transcript, 0x4f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7140),
                    mulmod(
                        mload(add(transcript, 0x6f00)),
                        mload(add(transcript, 0x4f80)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7160),
                    addmod(
                        mload(add(transcript, 0x70c0)),
                        mload(add(transcript, 0x7120)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1200)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1220)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1240)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7180), result)
                }
                mstore(
                    add(transcript, 0x71a0),
                    mulmod(
                        mload(add(transcript, 0x7180)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x71c0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x71a0))),
                        mload(add(transcript, 0x4fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x71e0),
                    mulmod(
                        mload(add(transcript, 0x6f00)),
                        mload(add(transcript, 0x4fa0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7200),
                    addmod(
                        mload(add(transcript, 0x7160)),
                        mload(add(transcript, 0x71c0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1260)),
                        mload(add(transcript, 0x4880)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1280)),
                            mload(add(transcript, 0x48a0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x12a0)),
                            mload(add(transcript, 0x48c0)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7220), result)
                }
                mstore(
                    add(transcript, 0x7240),
                    mulmod(
                        mload(add(transcript, 0x7220)),
                        mload(add(transcript, 0x4f00)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7260),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7240))),
                        mload(add(transcript, 0x4fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7280),
                    mulmod(
                        mload(add(transcript, 0x6f00)),
                        mload(add(transcript, 0x4fc0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x72a0),
                    addmod(
                        mload(add(transcript, 0x7200)),
                        mload(add(transcript, 0x7260)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x72c0),
                    mulmod(
                        mload(add(transcript, 0x72a0)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x72e0),
                    mulmod(
                        mload(add(transcript, 0x6f80)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7300),
                    mulmod(
                        mload(add(transcript, 0x7000)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7320),
                    mulmod(
                        mload(add(transcript, 0x70a0)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7340),
                    mulmod(
                        mload(add(transcript, 0x7140)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7360),
                    mulmod(
                        mload(add(transcript, 0x71e0)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7380),
                    mulmod(
                        mload(add(transcript, 0x7280)),
                        mload(add(transcript, 0x52c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x73a0),
                    addmod(
                        mload(add(transcript, 0x6ee0)),
                        mload(add(transcript, 0x72c0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x73c0),
                    mulmod(1, mload(add(transcript, 0x4d00)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x12c0)),
                        mload(add(transcript, 0x4900)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x12e0)),
                            mload(add(transcript, 0x4920)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x73e0), result)
                }
                mstore(
                    add(transcript, 0x7400),
                    mulmod(
                        mload(add(transcript, 0x73e0)),
                        mload(add(transcript, 0x4f20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7420),
                    mulmod(sub(f_q, mload(add(transcript, 0x7400))), 1, f_q)
                )
                mstore(
                    add(transcript, 0x7440),
                    mulmod(mload(add(transcript, 0x73c0)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1300)),
                        mload(add(transcript, 0x4900)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1320)),
                            mload(add(transcript, 0x4920)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7460), result)
                }
                mstore(
                    add(transcript, 0x7480),
                    mulmod(
                        mload(add(transcript, 0x7460)),
                        mload(add(transcript, 0x4f20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x74a0),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7480))),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x74c0),
                    mulmod(
                        mload(add(transcript, 0x73c0)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x74e0),
                    addmod(
                        mload(add(transcript, 0x7420)),
                        mload(add(transcript, 0x74a0)),
                        f_q
                    )
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x13a0)),
                        mload(add(transcript, 0x4900)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x13c0)),
                            mload(add(transcript, 0x4920)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7500), result)
                }
                mstore(
                    add(transcript, 0x7520),
                    mulmod(
                        mload(add(transcript, 0x7500)),
                        mload(add(transcript, 0x4f20)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7540),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7520))),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7560),
                    mulmod(
                        mload(add(transcript, 0x73c0)),
                        mload(add(transcript, 0x4f60)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7580),
                    addmod(
                        mload(add(transcript, 0x74e0)),
                        mload(add(transcript, 0x7540)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x75a0),
                    mulmod(
                        mload(add(transcript, 0x7580)),
                        mload(add(transcript, 0x52e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x75c0),
                    mulmod(
                        mload(add(transcript, 0x7440)),
                        mload(add(transcript, 0x52e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x75e0),
                    mulmod(
                        mload(add(transcript, 0x74c0)),
                        mload(add(transcript, 0x52e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7600),
                    mulmod(
                        mload(add(transcript, 0x7560)),
                        mload(add(transcript, 0x52e0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7620),
                    addmod(
                        mload(add(transcript, 0x73a0)),
                        mload(add(transcript, 0x75a0)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7640),
                    mulmod(1, mload(add(transcript, 0x4d40)), f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x1340)),
                        mload(add(transcript, 0x4940)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1360)),
                            mload(add(transcript, 0x4960)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x7660), result)
                }
                mstore(
                    add(transcript, 0x7680),
                    mulmod(
                        mload(add(transcript, 0x7660)),
                        mload(add(transcript, 0x4f40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x76a0),
                    mulmod(sub(f_q, mload(add(transcript, 0x7680))), 1, f_q)
                )
                mstore(
                    add(transcript, 0x76c0),
                    mulmod(mload(add(transcript, 0x7640)), 1, f_q)
                )
                {
                    let result := mulmod(
                        mload(add(transcript, 0x13e0)),
                        mload(add(transcript, 0x4940)),
                        f_q
                    )
                    result := addmod(
                        mulmod(
                            mload(add(transcript, 0x1400)),
                            mload(add(transcript, 0x4960)),
                            f_q
                        ),
                        result,
                        f_q
                    )
                    mstore(add(transcript, 0x76e0), result)
                }
                mstore(
                    add(transcript, 0x7700),
                    mulmod(
                        mload(add(transcript, 0x76e0)),
                        mload(add(transcript, 0x4f40)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7720),
                    mulmod(
                        sub(f_q, mload(add(transcript, 0x7700))),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7740),
                    mulmod(
                        mload(add(transcript, 0x7640)),
                        mload(add(transcript, 0x1460)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7760),
                    addmod(
                        mload(add(transcript, 0x76a0)),
                        mload(add(transcript, 0x7720)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7780),
                    mulmod(
                        mload(add(transcript, 0x7760)),
                        mload(add(transcript, 0x5300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x77a0),
                    mulmod(
                        mload(add(transcript, 0x76c0)),
                        mload(add(transcript, 0x5300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x77c0),
                    mulmod(
                        mload(add(transcript, 0x7740)),
                        mload(add(transcript, 0x5300)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x77e0),
                    addmod(
                        mload(add(transcript, 0x7620)),
                        mload(add(transcript, 0x7780)),
                        f_q
                    )
                )
                mstore(
                    add(transcript, 0x7800),
                    mulmod(1, mload(add(transcript, 0x4840)), f_q)
                )
                mstore(
                    add(transcript, 0x7820),
                    mulmod(1, mload(add(transcript, 0x1560)), f_q)
                )
                mstore(
                    add(transcript, 0x7840),
                    0x0000000000000000000000000000000000000000000000000000000000000001
                )
                mstore(
                    add(transcript, 0x7860),
                    0x0000000000000000000000000000000000000000000000000000000000000002
                )
                mstore(add(transcript, 0x7880), mload(add(transcript, 0x77e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7840),
                            0x60,
                            add(transcript, 0x7840),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x78a0), mload(add(transcript, 0x7840)))
                mstore(add(transcript, 0x78c0), mload(add(transcript, 0x7860)))
                mstore(add(transcript, 0x78e0), mload(add(transcript, 0x80)))
                mstore(add(transcript, 0x7900), mload(add(transcript, 0xa0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x78a0),
                            0x80,
                            add(transcript, 0x78a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7920), mload(add(transcript, 0xc0)))
                mstore(add(transcript, 0x7940), mload(add(transcript, 0xe0)))
                mstore(add(transcript, 0x7960), mload(add(transcript, 0x5820)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7920),
                            0x60,
                            add(transcript, 0x7920),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7980), mload(add(transcript, 0x78a0)))
                mstore(add(transcript, 0x79a0), mload(add(transcript, 0x78c0)))
                mstore(add(transcript, 0x79c0), mload(add(transcript, 0x7920)))
                mstore(add(transcript, 0x79e0), mload(add(transcript, 0x7940)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7980),
                            0x80,
                            add(transcript, 0x7980),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7a00), mload(add(transcript, 0x100)))
                mstore(add(transcript, 0x7a20), mload(add(transcript, 0x120)))
                mstore(add(transcript, 0x7a40), mload(add(transcript, 0x5840)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7a00),
                            0x60,
                            add(transcript, 0x7a00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7a60), mload(add(transcript, 0x7980)))
                mstore(add(transcript, 0x7a80), mload(add(transcript, 0x79a0)))
                mstore(add(transcript, 0x7aa0), mload(add(transcript, 0x7a00)))
                mstore(add(transcript, 0x7ac0), mload(add(transcript, 0x7a20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7a60),
                            0x80,
                            add(transcript, 0x7a60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7ae0), mload(add(transcript, 0x140)))
                mstore(add(transcript, 0x7b00), mload(add(transcript, 0x160)))
                mstore(add(transcript, 0x7b20), mload(add(transcript, 0x5860)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7ae0),
                            0x60,
                            add(transcript, 0x7ae0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7b40), mload(add(transcript, 0x7a60)))
                mstore(add(transcript, 0x7b60), mload(add(transcript, 0x7a80)))
                mstore(add(transcript, 0x7b80), mload(add(transcript, 0x7ae0)))
                mstore(add(transcript, 0x7ba0), mload(add(transcript, 0x7b00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7b40),
                            0x80,
                            add(transcript, 0x7b40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7bc0), mload(add(transcript, 0x180)))
                mstore(add(transcript, 0x7be0), mload(add(transcript, 0x1a0)))
                mstore(add(transcript, 0x7c00), mload(add(transcript, 0x5880)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7bc0),
                            0x60,
                            add(transcript, 0x7bc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7c20), mload(add(transcript, 0x7b40)))
                mstore(add(transcript, 0x7c40), mload(add(transcript, 0x7b60)))
                mstore(add(transcript, 0x7c60), mload(add(transcript, 0x7bc0)))
                mstore(add(transcript, 0x7c80), mload(add(transcript, 0x7be0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7c20),
                            0x80,
                            add(transcript, 0x7c20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7ca0), mload(add(transcript, 0x1c0)))
                mstore(add(transcript, 0x7cc0), mload(add(transcript, 0x1e0)))
                mstore(add(transcript, 0x7ce0), mload(add(transcript, 0x58a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7ca0),
                            0x60,
                            add(transcript, 0x7ca0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7d00), mload(add(transcript, 0x7c20)))
                mstore(add(transcript, 0x7d20), mload(add(transcript, 0x7c40)))
                mstore(add(transcript, 0x7d40), mload(add(transcript, 0x7ca0)))
                mstore(add(transcript, 0x7d60), mload(add(transcript, 0x7cc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7d00),
                            0x80,
                            add(transcript, 0x7d00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7d80), mload(add(transcript, 0x200)))
                mstore(add(transcript, 0x7da0), mload(add(transcript, 0x220)))
                mstore(add(transcript, 0x7dc0), mload(add(transcript, 0x58c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7d80),
                            0x60,
                            add(transcript, 0x7d80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7de0), mload(add(transcript, 0x7d00)))
                mstore(add(transcript, 0x7e00), mload(add(transcript, 0x7d20)))
                mstore(add(transcript, 0x7e20), mload(add(transcript, 0x7d80)))
                mstore(add(transcript, 0x7e40), mload(add(transcript, 0x7da0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7de0),
                            0x80,
                            add(transcript, 0x7de0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7e60), mload(add(transcript, 0x240)))
                mstore(add(transcript, 0x7e80), mload(add(transcript, 0x260)))
                mstore(add(transcript, 0x7ea0), mload(add(transcript, 0x58e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7e60),
                            0x60,
                            add(transcript, 0x7e60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7ec0), mload(add(transcript, 0x7de0)))
                mstore(add(transcript, 0x7ee0), mload(add(transcript, 0x7e00)))
                mstore(add(transcript, 0x7f00), mload(add(transcript, 0x7e60)))
                mstore(add(transcript, 0x7f20), mload(add(transcript, 0x7e80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7ec0),
                            0x80,
                            add(transcript, 0x7ec0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7f40), mload(add(transcript, 0x280)))
                mstore(add(transcript, 0x7f60), mload(add(transcript, 0x2a0)))
                mstore(add(transcript, 0x7f80), mload(add(transcript, 0x6b40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x7f40),
                            0x60,
                            add(transcript, 0x7f40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x7fa0), mload(add(transcript, 0x7ec0)))
                mstore(add(transcript, 0x7fc0), mload(add(transcript, 0x7ee0)))
                mstore(add(transcript, 0x7fe0), mload(add(transcript, 0x7f40)))
                mstore(add(transcript, 0x8000), mload(add(transcript, 0x7f60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x7fa0),
                            0x80,
                            add(transcript, 0x7fa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8020), mload(add(transcript, 0x2c0)))
                mstore(add(transcript, 0x8040), mload(add(transcript, 0x2e0)))
                mstore(add(transcript, 0x8060), mload(add(transcript, 0x6b60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8020),
                            0x60,
                            add(transcript, 0x8020),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8080), mload(add(transcript, 0x7fa0)))
                mstore(add(transcript, 0x80a0), mload(add(transcript, 0x7fc0)))
                mstore(add(transcript, 0x80c0), mload(add(transcript, 0x8020)))
                mstore(add(transcript, 0x80e0), mload(add(transcript, 0x8040)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8080),
                            0x80,
                            add(transcript, 0x8080),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8100), mload(add(transcript, 0x300)))
                mstore(add(transcript, 0x8120), mload(add(transcript, 0x320)))
                mstore(add(transcript, 0x8140), mload(add(transcript, 0x6b80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8100),
                            0x60,
                            add(transcript, 0x8100),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8160), mload(add(transcript, 0x8080)))
                mstore(add(transcript, 0x8180), mload(add(transcript, 0x80a0)))
                mstore(add(transcript, 0x81a0), mload(add(transcript, 0x8100)))
                mstore(add(transcript, 0x81c0), mload(add(transcript, 0x8120)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8160),
                            0x80,
                            add(transcript, 0x8160),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x81e0), mload(add(transcript, 0x3e0)))
                mstore(add(transcript, 0x8200), mload(add(transcript, 0x400)))
                mstore(add(transcript, 0x8220), mload(add(transcript, 0x6ba0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x81e0),
                            0x60,
                            add(transcript, 0x81e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8240), mload(add(transcript, 0x8160)))
                mstore(add(transcript, 0x8260), mload(add(transcript, 0x8180)))
                mstore(add(transcript, 0x8280), mload(add(transcript, 0x81e0)))
                mstore(add(transcript, 0x82a0), mload(add(transcript, 0x8200)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8240),
                            0x80,
                            add(transcript, 0x8240),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x82c0), mload(add(transcript, 0x460)))
                mstore(add(transcript, 0x82e0), mload(add(transcript, 0x480)))
                mstore(add(transcript, 0x8300), mload(add(transcript, 0x6bc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x82c0),
                            0x60,
                            add(transcript, 0x82c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8320), mload(add(transcript, 0x8240)))
                mstore(add(transcript, 0x8340), mload(add(transcript, 0x8260)))
                mstore(add(transcript, 0x8360), mload(add(transcript, 0x82c0)))
                mstore(add(transcript, 0x8380), mload(add(transcript, 0x82e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8320),
                            0x80,
                            add(transcript, 0x8320),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x83a0),
                    0x1c5666598315fe6733e0b73b00df436b4e0917c7c18df9f6f8295dd26b55dd21
                )
                mstore(
                    add(transcript, 0x83c0),
                    0x1e948bc45dd735c737d538ef8d392e3df174ed4ef9ebc6f4935988794a11eaad
                )
                mstore(add(transcript, 0x83e0), mload(add(transcript, 0x6be0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x83a0),
                            0x60,
                            add(transcript, 0x83a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8400), mload(add(transcript, 0x8320)))
                mstore(add(transcript, 0x8420), mload(add(transcript, 0x8340)))
                mstore(add(transcript, 0x8440), mload(add(transcript, 0x83a0)))
                mstore(add(transcript, 0x8460), mload(add(transcript, 0x83c0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8400),
                            0x80,
                            add(transcript, 0x8400),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8480),
                    0x0a450e58173ff2752ee9abe341727e6093b146a8a35074d2fa963267835d70f9
                )
                mstore(
                    add(transcript, 0x84a0),
                    0x04936dcc176315c74e265dae9285d66a9f001296db7cb0b2b57103aa46af2a4c
                )
                mstore(add(transcript, 0x84c0), mload(add(transcript, 0x6c00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8480),
                            0x60,
                            add(transcript, 0x8480),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x84e0), mload(add(transcript, 0x8400)))
                mstore(add(transcript, 0x8500), mload(add(transcript, 0x8420)))
                mstore(add(transcript, 0x8520), mload(add(transcript, 0x8480)))
                mstore(add(transcript, 0x8540), mload(add(transcript, 0x84a0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x84e0),
                            0x80,
                            add(transcript, 0x84e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8560),
                    0x2d344f5d4336a908ee5dd0f1fb43c63ce9749d783a20389bb050a980e854c751
                )
                mstore(
                    add(transcript, 0x8580),
                    0x15a784285268e22236d29460a53740727906c70d30ce4b1fb20c59e8ed3428c4
                )
                mstore(add(transcript, 0x85a0), mload(add(transcript, 0x6c20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8560),
                            0x60,
                            add(transcript, 0x8560),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x85c0), mload(add(transcript, 0x84e0)))
                mstore(add(transcript, 0x85e0), mload(add(transcript, 0x8500)))
                mstore(add(transcript, 0x8600), mload(add(transcript, 0x8560)))
                mstore(add(transcript, 0x8620), mload(add(transcript, 0x8580)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x85c0),
                            0x80,
                            add(transcript, 0x85c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8640),
                    0x236a9b762cb5c528cf153f7075972c3d1a5d31df01457c1a4d294db229d70aa5
                )
                mstore(
                    add(transcript, 0x8660),
                    0x1022356fd2168794cf4897d74387383af1a1a98c16725b04136543ccab0adce0
                )
                mstore(add(transcript, 0x8680), mload(add(transcript, 0x6c40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8640),
                            0x60,
                            add(transcript, 0x8640),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x86a0), mload(add(transcript, 0x85c0)))
                mstore(add(transcript, 0x86c0), mload(add(transcript, 0x85e0)))
                mstore(add(transcript, 0x86e0), mload(add(transcript, 0x8640)))
                mstore(add(transcript, 0x8700), mload(add(transcript, 0x8660)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x86a0),
                            0x80,
                            add(transcript, 0x86a0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8720),
                    0x0fe6d9475567981033493fab1d281ddb31987474d831c628b71a22bd7cc0b51c
                )
                mstore(
                    add(transcript, 0x8740),
                    0x11f7f243d4e52ce8f83597de0835799046a2741cfddae859fb6580a3df14b0f6
                )
                mstore(add(transcript, 0x8760), mload(add(transcript, 0x6c60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8720),
                            0x60,
                            add(transcript, 0x8720),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8780), mload(add(transcript, 0x86a0)))
                mstore(add(transcript, 0x87a0), mload(add(transcript, 0x86c0)))
                mstore(add(transcript, 0x87c0), mload(add(transcript, 0x8720)))
                mstore(add(transcript, 0x87e0), mload(add(transcript, 0x8740)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8780),
                            0x80,
                            add(transcript, 0x8780),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8800),
                    0x11a65ffc815a7a4334e5b08a0fb284667fc7bc98efa3edfacef50cd2ea773382
                )
                mstore(
                    add(transcript, 0x8820),
                    0x043dfb86a43290a71d49aaa11e20de7c0a7bc51b1b23e0e575ace45d5f681aa6
                )
                mstore(add(transcript, 0x8840), mload(add(transcript, 0x6c80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8800),
                            0x60,
                            add(transcript, 0x8800),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8860), mload(add(transcript, 0x8780)))
                mstore(add(transcript, 0x8880), mload(add(transcript, 0x87a0)))
                mstore(add(transcript, 0x88a0), mload(add(transcript, 0x8800)))
                mstore(add(transcript, 0x88c0), mload(add(transcript, 0x8820)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8860),
                            0x80,
                            add(transcript, 0x8860),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x88e0),
                    0x06a384d60c515b00b9fb93ddcda85b229e2a438077a6fa12a98cbf2bca3ece9a
                )
                mstore(
                    add(transcript, 0x8900),
                    0x2472aa32e2aa3324fa5635722c8f698bf1ba3bdab55b2393c6395c8c5ec0e495
                )
                mstore(add(transcript, 0x8920), mload(add(transcript, 0x6ca0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x88e0),
                            0x60,
                            add(transcript, 0x88e0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8940), mload(add(transcript, 0x8860)))
                mstore(add(transcript, 0x8960), mload(add(transcript, 0x8880)))
                mstore(add(transcript, 0x8980), mload(add(transcript, 0x88e0)))
                mstore(add(transcript, 0x89a0), mload(add(transcript, 0x8900)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8940),
                            0x80,
                            add(transcript, 0x8940),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x89c0),
                    0x198fa27c925cfd44a2e3c192f229e2eb163dba48a9afe91cfed66e8557410f04
                )
                mstore(
                    add(transcript, 0x89e0),
                    0x22b881803968e9b77d9a8c80b98039a540ee5238a21a99bf2e01f977ff305202
                )
                mstore(add(transcript, 0x8a00), mload(add(transcript, 0x6cc0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x89c0),
                            0x60,
                            add(transcript, 0x89c0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8a20), mload(add(transcript, 0x8940)))
                mstore(add(transcript, 0x8a40), mload(add(transcript, 0x8960)))
                mstore(add(transcript, 0x8a60), mload(add(transcript, 0x89c0)))
                mstore(add(transcript, 0x8a80), mload(add(transcript, 0x89e0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8a20),
                            0x80,
                            add(transcript, 0x8a20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8aa0),
                    0x1a3b71bb4dc777bda760407b06c6d2d86a5c175c7b477d74af2a1dd7672bfeb2
                )
                mstore(
                    add(transcript, 0x8ac0),
                    0x300d40e47d6cda6c45a4fee51519275ddd2d2bfd5f624f8aa3710a93483c877b
                )
                mstore(add(transcript, 0x8ae0), mload(add(transcript, 0x6ce0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8aa0),
                            0x60,
                            add(transcript, 0x8aa0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8b00), mload(add(transcript, 0x8a20)))
                mstore(add(transcript, 0x8b20), mload(add(transcript, 0x8a40)))
                mstore(add(transcript, 0x8b40), mload(add(transcript, 0x8aa0)))
                mstore(add(transcript, 0x8b60), mload(add(transcript, 0x8ac0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8b00),
                            0x80,
                            add(transcript, 0x8b00),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8b80),
                    0x221dc62fdb011aed5ef077ffc116b589100e5147ebc52ea26547bdc968f0d1fe
                )
                mstore(
                    add(transcript, 0x8ba0),
                    0x2fc2fa60263eebc29bc71510e01bd2bfa75f4e032630dbd155893a28c20d0547
                )
                mstore(add(transcript, 0x8bc0), mload(add(transcript, 0x6d00)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8b80),
                            0x60,
                            add(transcript, 0x8b80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8be0), mload(add(transcript, 0x8b00)))
                mstore(add(transcript, 0x8c00), mload(add(transcript, 0x8b20)))
                mstore(add(transcript, 0x8c20), mload(add(transcript, 0x8b80)))
                mstore(add(transcript, 0x8c40), mload(add(transcript, 0x8ba0)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8be0),
                            0x80,
                            add(transcript, 0x8be0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8c60),
                    0x0202128d30b34f4ef11f9cd718711559144845b367c8b97cf3cd4017d635034a
                )
                mstore(
                    add(transcript, 0x8c80),
                    0x19ac23de7bbba1cd1840ab78a060ddae2b4efc675a623a6ce3f5e3bf92795382
                )
                mstore(add(transcript, 0x8ca0), mload(add(transcript, 0x6d20)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8c60),
                            0x60,
                            add(transcript, 0x8c60),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8cc0), mload(add(transcript, 0x8be0)))
                mstore(add(transcript, 0x8ce0), mload(add(transcript, 0x8c00)))
                mstore(add(transcript, 0x8d00), mload(add(transcript, 0x8c60)))
                mstore(add(transcript, 0x8d20), mload(add(transcript, 0x8c80)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8cc0),
                            0x80,
                            add(transcript, 0x8cc0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8d40),
                    0x0aca71909a4fc7ce72576ef169f7b3c23beb1548ffd2708acffac7f43eda0bba
                )
                mstore(
                    add(transcript, 0x8d60),
                    0x0176603cd95aa97ad7023fa418a4f21413b5cdfef00b57a8cdf884e676aed9a7
                )
                mstore(add(transcript, 0x8d80), mload(add(transcript, 0x6d40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8d40),
                            0x60,
                            add(transcript, 0x8d40),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8da0), mload(add(transcript, 0x8cc0)))
                mstore(add(transcript, 0x8dc0), mload(add(transcript, 0x8ce0)))
                mstore(add(transcript, 0x8de0), mload(add(transcript, 0x8d40)))
                mstore(add(transcript, 0x8e00), mload(add(transcript, 0x8d60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8da0),
                            0x80,
                            add(transcript, 0x8da0),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8e20),
                    0x115375c4589b6922ad9de276f551894adfb7815609d21b0ee5771d74eab3c3d7
                )
                mstore(
                    add(transcript, 0x8e40),
                    0x27ebffe5633b945283153af352cec4d071ce33eebfb736f726046a74202aa72a
                )
                mstore(add(transcript, 0x8e60), mload(add(transcript, 0x6d60)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x7,
                            add(transcript, 0x8e20),
                            0x60,
                            add(transcript, 0x8e20),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(add(transcript, 0x8e80), mload(add(transcript, 0x8da0)))
                mstore(add(transcript, 0x8ea0), mload(add(transcript, 0x8dc0)))
                mstore(add(transcript, 0x8ec0), mload(add(transcript, 0x8e20)))
                mstore(add(transcript, 0x8ee0), mload(add(transcript, 0x8e40)))
                success := and(
                    eq(
                        staticcall(
                            gas(),
                            0x6,
                            add(transcript, 0x8e80),
                            0x80,
                            add(transcript, 0x8e80),
                            0x40
                        ),
                        1
                    ),
                    success
                )
                mstore(
                    add(transcript, 0x8f00),
                    0x101ce953d97b16794d7f4554d2840ab6119f63bcf5aab04db70802ec73d5d0b1
                )
                mstore(
                    add(transcript, 0x8f20),
                    0x175cda852110c69273449da6099fcd97e800d130a1524ee4a88db65d213e1bd9
                )
            }
        }
        bytes memory transcriptBytes = abi.encode(transcript);
        // bytes32[] memory newTranscript = new bytes32[](1323);
        // for(uint i=0; i<_transcript.length; i++) {
        //     newTranscript[i] = transcript[i];
        // }
        // require(newTranscript.length == 1323, "newTranscript length is not 1323");
        return (success, transcriptBytes);
    }
}
