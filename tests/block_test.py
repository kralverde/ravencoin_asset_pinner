import os

from ..pinner import asset_info_from_block


def ipfs_hashes_from_block(block):
    for _, _, ipfs_hash in asset_info_from_block(block):
        yield ipfs_hash


def block_hex_for_height(height):
    block_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", f"block_{height}.hex"
    )
    with open(block_file, "r") as f:
        return f.read()


def hashes_for_block_height(height):
    block_h = block_hex_for_height(height)
    block = bytes.fromhex(block_h)
    yield from ipfs_hashes_from_block(block)


def test_pre_kawpow():
    for _ in hashes_for_block_height(1):
        pass


def test_post_kawpow():
    for _ in hashes_for_block_height(1219752):
        pass


def test_large():
    for _ in hashes_for_block_height(3227009):
        pass


def test_error_case_1():
    for _ in hashes_for_block_height(1159647):
        pass

    for _ in hashes_for_block_height(1159646):
        pass


def test_error_case_2():
    for _ in hashes_for_block_height(1231871):
        pass

    for _ in hashes_for_block_height(1231872):
        pass


def test_asset():
    expected_hashes = {"QmNgcELSEQCQKi1Z9sV6rvhnjb1PGDjHhVQfmYgDTYFfr8"}
    assert not expected_hashes.symmetric_difference(hashes_for_block_height(561033))


def test_broadcast():
    expected_hashes = {"QmV97xJXGN7raLPRGUXkvqttX8fkn6nH9iQhLXF1xKeUVK"}
    assert not expected_hashes.symmetric_difference(hashes_for_block_height(3200657))


def test_reissue():
    expected_hashes = {"QmWU32M78iB5eRCHBTmubR3NFSJRvnYcuE899Yp8wn3dkH"}
    assert not expected_hashes.symmetric_difference(hashes_for_block_height(3222960))
