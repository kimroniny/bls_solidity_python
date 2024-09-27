import pytest
from brownie import TestBLS, accounts, TestBLS2

from py_ecc.optimized_bn128 import *
from eth_hash.auto import keccak
from typing import Tuple
from eth_utils import encode_hex

# used for helped aggregation
def get_public_key_G1(secret_key: int) -> Tuple[FQ, FQ, FQ]:
    return multiply(G1, secret_key)


def get_public_key(secret_key: int) -> Tuple[FQ2, FQ2, FQ2]:
    return multiply(G2, secret_key)


def sign(message: Tuple[FQ, FQ, FQ], secret_key: int):
    return multiply(message, secret_key)


def aggregate_signatures(signatures: list[Tuple[FQ, FQ, FQ]]) -> Tuple[FQ, FQ, FQ]:
    res = signatures[0]
    for signature in signatures[1:]:
        res = add(res, signature)
    return res


def aggregate_public_keys(pubkeys: list[Tuple[FQ2, FQ2, FQ2]]) -> Tuple[FQ2, FQ2, FQ2]:
    res = pubkeys[0]
    for pubkey in pubkeys[1:]:
        res = add(res, pubkey)
    return res


# used for helped aggregation
def aggregate_public_keys_G1(pubkeys: list[Tuple[FQ, FQ, FQ]]) -> Tuple[FQ, FQ, FQ]:
    res = pubkeys[0]
    for pubkey in pubkeys[1:]:
        res = add(res, pubkey)
    return res


def hash_to_point(data: str):
    return map_to_point(keccak(data))


def map_to_point(x):
    pass


def sqrt(x_sqaure: int) -> Tuple[int, bool]:
    pass


def parse_solc_G1(solc_G1: Tuple[int, int]):
    x, y = solc_G1
    return FQ(x), FQ(y), FQ(1)


def format_G1(g1_element: Tuple[FQ, FQ, FQ]) -> Tuple[FQ, FQ]:
    x, y = normalize(g1_element)
    return (str(x), str(y))


def format_G2(g2_element: Tuple[FQ2, FQ2, FQ2]) -> Tuple[FQ2, FQ2]:
    x, y = normalize(g2_element)
    x1, x2 = x.coeffs
    y1, y2 = y.coeffs
    return x1, x2, y1, y2


def test_main():
    test_bls = accounts[0].deploy(TestBLS)

    secret_key = 2

    public_key = get_public_key(secret_key)
    data = encode_hex("123")
    print("data", data)
    message_solc = tuple(test_bls.hashToPoint(data))
    message = parse_solc_G1(message_solc)
    sig = sign(message, secret_key)
    message_solc_2 = format_G1(message)
    assert message_solc_2 == message_solc
    pubkey_solc = format_G2(public_key)
    sig_solc = format_G1(sig)
    print(f"pubkey_solc: {pubkey_solc}")
    print(f"sig_solc: {sig_solc}")
    print(f"message: {message}")
    print(f"message_solc_2: {message_solc_2}")

    assert test_bls.verifySingle(sig_solc, pubkey_solc, message_solc_2)


def test_g2_subgroup_check():
    valid_G2 = multiply(G2, 5)
    assert is_on_curve(valid_G2, b2)

    # TODO: how do you create invalid G2?
    test_bls = accounts[0].deploy(TestBLS)

    assert test_bls.isOnSubgroupG2Naive(format_G2(valid_G2))

    gasCost = test_bls.isOnSubgroupG2NaiveGasCost(format_G2(valid_G2))
    print("G2 subgroup check naive", gasCost)

    assert test_bls.isOnSubgroupG2DLZZ(format_G2(valid_G2))

    gasCost = test_bls.isOnSubgroupG2DLZZGasCost(format_G2(valid_G2))
    print("G2 subgroup check DLZZ", gasCost)


def test_aggregation():
    test_bls = accounts[0].deploy(TestBLS)

    secret_key1 = 123
    secret_key2 = 456

    public_key1 = get_public_key(secret_key1)
    public_key1_solc = format_G2(public_key1)
    public_key2 = get_public_key(secret_key2)
    public_key2_solc = format_G2(public_key2)
    agg_public_key = aggregate_public_keys([public_key1, public_key2])
    agg_pubkey_solc = format_G2(agg_public_key)

    data = encode_hex("fooooo")
    message_solc = tuple(test_bls.hashToPoint(data))
    message = parse_solc_G1(message_solc)

    sig1 = sign(message, secret_key1)
    sig2 = sign(message, secret_key2)
    agg_sig = aggregate_signatures([sig1, sig2])
    agg_sig_solc = format_G1(agg_sig)

    # verifyMultiple is safer than verifySignle as it takes individual
    # public keys as arguments and aggregates them on chain,
    # preventing the rouge key attack.
    assert test_bls.verifyMultiple(
        agg_sig_solc, [public_key1_solc, public_key2_solc], [message_solc, message_solc]
    )

    # using verifySignle just to test aggregate_public_keys
    assert test_bls.verifySingle(agg_sig_solc, agg_pubkey_solc, message_solc)


# Helped aggregation : https://geometry.xyz/notebook/Optimized-BLS-multisignatures-on-EVM
# Making verification of multisignatures efficient
# each signer submits two public keys(in G1&G2) corresponding to their secret key
def test_helped_aggregation():
    test_bls = accounts[0].deploy(TestBLS)

    valid_G1 = multiply(G1, 5)
    assert is_on_curve(valid_G1, b)
    valid_G2 = multiply(G2, 5)
    assert is_on_curve(valid_G2, b2)

    data = encode_hex("fooooo")
    message_solc = tuple(test_bls.hashToPoint(data))
    message = parse_solc_G1(message_solc)

    secret_key1 = 123
    secret_key2 = 456

    sig1 = sign(message, secret_key1)
    sig1_solc = format_G1(sig1)
    sig2 = sign(message, secret_key2)
    sig2_solc = format_G1(sig2)
    agg_sig = aggregate_signatures([sig1, sig2])
    agg_sig_solc = format_G1(agg_sig)

    public_key1G1 = get_public_key_G1(secret_key1)
    public_key1G1_solc = format_G1(public_key1G1)
    public_key1G2 = get_public_key(secret_key1)
    public_key1G2_solc = format_G2(public_key1G2)
    assert test_bls.verifyHelpedAggregationPublicKeys(
        public_key1G1_solc, public_key1G2_solc
    )
    assert test_bls.verifyHelpedAggregationPublicKeysRec(
        public_key1G1_solc, public_key1G2_solc, data, sig1_solc
    )

    public_key2G1 = get_public_key_G1(secret_key2)
    public_key2G1_solc = format_G1(public_key2G1)
    public_key2G2 = get_public_key(secret_key2)
    public_key2G2_solc = format_G2(public_key2G2)
    assert test_bls.verifyHelpedAggregationPublicKeys(
        public_key2G1_solc, public_key2G2_solc
    )
    assert test_bls.verifyHelpedAggregationPublicKeysRec(
        public_key2G1_solc, public_key2G2_solc, data, sig2_solc
    )

    agg_public_key_G1 = aggregate_public_keys_G1([public_key1G1, public_key2G1])
    agg_pubkey_G1_solc = format_G1(agg_public_key_G1)

    agg_public_key_G2 = aggregate_public_keys([public_key1G2, public_key2G2])
    agg_pubkey_G2_solc = format_G2(agg_public_key_G2)

    assert test_bls.verifyHelpedAggregationPublicKeysMultiple(
        agg_pubkey_G1_solc, [public_key1G2_solc, public_key2G2_solc]
    )
    assert test_bls.verifyHelpedAggregationPublicKeysRec(
        agg_pubkey_G1_solc, agg_pubkey_G2_solc, data, agg_sig_solc
    )

def test_rust():
    # test_bls = accounts[0].deploy(TestBLS)

    secret_key1 = int.from_bytes(bytes.fromhex("2c5023181035143cab661cecdabd7b85242c93c1f2e8493fc2458ba781fcb6a1"), "big")
    # secret_key2 = int.from_bytes(bytes.fromhex("03589c8ef556444912c011964bc7f4c07d75331fe1a21fde8ab88338c9b58b05"), "big")

    public_key1 = get_public_key(secret_key1)
    # public_key2 = get_public_key(secret_key2)

    print("public_key1", public_key1)
    # print("public_key2", public_key2)

def test_from_asecurity():
    test_bls = accounts[0].deploy(TestBLS)
    secret_key1 = 24288545526422479530261015179658692994640912157714313922068929040617865560652

    public_key = get_public_key(secret_key1)
    print("public_key", public_key)

    data = encode_hex("hello")
    message_solc = tuple(test_bls.hashToPoint(data))
    print("message_solc", message_solc)
    message = parse_solc_G1(message_solc)
    print("message", message)

def test_const():
    print(FQ2.one())
    print(G2)

def test_secret_key():
    secret_key = 2
    public_key = get_public_key(secret_key)
    print("public_key", public_key)
    print("public_key[0]", public_key[0].coeffs[0].real)
    print("public_key[1]", public_key[1].coeffs[0].real)
    print("public_key[2]", public_key[2].coeffs[0].real)

def test_message():
    test_bls = accounts[0].deploy(TestBLS)
    secret_key = 2
    data = encode_hex("123")
    print("data", data)
    message_solc = tuple(test_bls.hashToPoint(data))
    message = parse_solc_G1(message_solc)
    print("message", message)
    signature = sign(message, secret_key)
    print("signature", signature)

import pytest

@pytest.mark.parametrize("agg_pubkey_solc, message_solc, agg_sig_solc", [
    (
        (
            18029695676650738226693292988307914797657423701064905010927197838374790804409, 
            14583779054894525174450323658765874724019480979794335525732096752006891875705, 
            2140229616977736810657479771656733941598412651537078903776637920509952744750, 
            11474861747383700316476719153975578001603231366361248090558603872215261634898
        ),
        (
            10111300782571508338418048025387181641517807407435169233393164644149157704140, 
            10450603913594475768276458419568026298173867283087113348690895055250290398446
        ),
        (
            20813053432304495890332325029260451662595802894919270065444023335291157259601, 
            16830900552633585392159464280600090697025967583440980276204126829064474067438
        )
    ),
    (
        (
            10191129150170504690859455063377241352678147020731325090942140630855943625622, 
            12345624066896925082600651626583520268054356403303305150512393106955803260718, 
            16727484375212017249697795760885267597317766655549468217180521378213906474374, 
            13790151551682513054696583104432356791070435696840691503641536676885931241944
        ),
        (
            10111300782571508338418048025387181641517807407435169233393164644149157704140, 
            10450603913594475768276458419568026298173867283087113348690895055250290398446
        ),
        (
            16642848843319367059691756307058073578276851713211986720165693631402684423230, 
            8705607815824455334580435833838955806066717384820118915001976283764811128868
        )
    )
])
def test_verify_onchain(agg_pubkey_solc, message_solc, agg_sig_solc):
    test_bls = accounts[0].deploy(TestBLS)    
    assert test_bls.verifySingle(agg_sig_solc, agg_pubkey_solc, message_solc)
    assert test_bls.isValidPublicKey(agg_pubkey_solc)

def test_verify_onchain2():
    test_bls = accounts[0].deploy(TestBLS)    
    
    agg_pubkey_solc = (
        18029695676650738226693292988307914797657423701064905010927197838374790804409, 
        14583779054894525174450323658765874724019480979794335525732096752006891875705, 
        2140229616977736810657479771656733941598412651537078903776637920509952744750, 
        11474861747383700316476719153975578001603231366361248090558603872215261634898
    )
    message_solc = (
        10111300782571508338418048025387181641517807407435169233393164644149157704140, 
        10450603913594475768276458419568026298173867283087113348690895055250290398446
    )
    agg_sig_solc = (
        20813053432304495890332325029260451662595802894919270065444023335291157259601, 
        16830900552633585392159464280600090697025967583440980276204126829064474067438
    )
    
    assert test_bls.verifySingle(agg_sig_solc, agg_pubkey_solc, message_solc)
    assert test_bls.isValidPublicKey(agg_pubkey_solc)

def test_hash_to_point():
    data = b"123"
    result = hash_to_point(data)
    print("result", result)

def test_calculation():
    x = add(G2, G2)
    print("x", x)
    formal_x = format_G2(x)
    print("formal_x", formal_x)

def test_double():
    pt = (2,3,1)
    x, y, z = pt
    W = 3 * x * x
    S = y * z
    B = x * y * S
    H = W * W - 8 * B
    S_squared = S * S
    newx = 2 * H * S
    newy = W * (4 * B - H) - 8 * y * y * S_squared
    newz = 8 * S * S_squared
    print(newx, newy, newz)

def test_aggregation():
    test_bls = accounts[0].deploy(TestBLS)

    secret_key1 = 1
    secret_key2 = 2
    secret_key3 = 3

    public_key1 = get_public_key(secret_key1)
    public_key1_solc = format_G2(public_key1)
    public_key2 = get_public_key(secret_key2)
    public_key2_solc = format_G2(public_key2)
    public_key3 = get_public_key(secret_key3)
    public_key3_solc = format_G2(public_key3)
    
    agg_public_key = aggregate_public_keys([public_key1, public_key2, public_key3])
    agg_pubkey_solc = format_G2(agg_public_key)

    data = encode_hex("fooooo")
    message_solc = tuple(test_bls.hashToPoint(data))
    message = parse_solc_G1(message_solc)

    sig1 = sign(message, secret_key1)
    sig2 = sign(message, secret_key2)
    agg_sig = aggregate_signatures([sig1, sig2])
    agg_sig_solc = format_G1(agg_sig)

    # verifyMultiple is safer than verifySignle as it takes individual
    # public keys as arguments and aggregates them on chain,
    # preventing the rouge key attack.
    assert test_bls.verifyMultiple(
        agg_sig_solc, [public_key1_solc, public_key2_solc], [message_solc, message_solc]
    )

    # using verifySignle just to test aggregate_public_keys
    assert test_bls.verifySingle(agg_sig_solc, agg_pubkey_solc, message_solc)

def test_hash_to_point_2():
    test_bls = accounts[0].deploy(TestBLS2)
    domain = b'testing-evmbls'
    msg = b'123'
    message_solc = tuple(test_bls.hashToPoint(domain, msg))
    print("message_solc", message_solc)

def test_hash_to_field():
    test_bls = accounts[0].deploy(TestBLS2)
    domain = b'testing-evmbls'
    msg = b'abc'
    message_solc = tuple(test_bls.hashToField(domain, msg))
    print("message_solc", message_solc)

def test_expand_msg_to_96():
    test_bls = accounts[0].deploy(TestBLS2)
    domain = b'QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_'
    msg = b'abc'
    message_solc = test_bls.expandMsgTo96(domain, msg)
    print("message_solc", message_solc)

def test_expand_msg_to_96_2():
    test_bls = accounts[0].deploy(TestBLS2)
    domain = b'testing-evmbls'
    msg = b'abc'
    message_solc = test_bls.expandMsgTo96(domain, msg)
    print("message_solc", message_solc)

if __name__ == "__main__":
    main()