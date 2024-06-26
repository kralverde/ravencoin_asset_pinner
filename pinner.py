import aiohttp
import asyncio
import base58
import json
import os
import re
import traceback

from typing import Optional, Set, Tuple, Dict, List
from multiformats import CID

KAWPOW_ACTIVATION_TIMESTAMP = 1588788000
# KAWPOW_ACTIVATION_TIMESTAMP = 1585159200
ASSET_PREFIX = b"rvn"
MAX_TASK_SIZE = 50
RETRY_PROPORTION = 0.5
MAX_TASK_RESTART_PROPORTION = 0.75
MAX_WAIT_SEC = 20 * 60
MAX_DOWNLOAD_SIZE = 1024 * 1024
WINDOW_SIZE = 128
CID_REGEX = re.compile(
    rb"Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[A-Za-z2-7]{58,}|B[A-Z2-7]{58,}|z[1-9A-HJ-NP-Za-km-z]{48,}|F[0-9A-F]{50,}"
)
MAX_BLOCKS_QUICK_RETRY = 60 * 2  # 2 hours
BLOCKS_TO_PREFETCH = 20


class BytesReaderException(Exception):
    def __init__(self, data, index, message):
        self.data = data
        self.index = index
        self.message = message

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"BytesReaderException({self.message})"

    def print_error(self):
        first = self.data[: self.index].hex()
        ptr = self.data[self.index : self.index + 1].hex()
        last = self.data[self.index + 1 :].hex()
        return f"{first} | {ptr} | {last}"


class BytesReader:
    def __init__(self, b: bytes):
        self.data = b
        self.ptr = 0

    def seek(self, i: int):
        assert i > 0, "must be positive"
        assert i < len(self.data), "out of bounds"
        self.ptr = i

    def peek_next_u8(self):
        return self.data[self.ptr]

    def read_next_u8(self):
        data = self.read(1)
        return data[0]

    def read(self, i: int):
        if (self.ptr + i) > len(self.data):
            raise BytesReaderException(
                self.data,
                self.ptr,
                f"Out of bounds (Want: {i}, Have: {len(self.data) - self.ptr})",
            )
        result = self.data[self.ptr : self.ptr + i]
        self.ptr += i
        return result

    def can_read(self, i: int):
        return (self.ptr + i) <= len(self.data)

    def read_var_int(self):
        val = self.read_next_u8()
        if val < 0xFD:
            return val
        if val == 0xFD:
            return int.from_bytes(self.read(2), "little")
        if val == 0xFE:
            return int.from_bytes(self.read(4), "little")
        return int.from_bytes(self.read(8), "little")

    def read_script(self):
        val = self.read_next_u8()
        if val <= 0x4E:
            if val == 0x4C:
                len = self.read_next_u8()
                return val, self.read(len)
            if val == 0x4D:
                len = int.from_bytes(self.read(2), "little")
                return val, self.read(len)
            if val == 0x4E:
                len = int.from_bytes(self.read(4), "little")
                return val, self.read(len)
            return val, self.read(val)
        return val, None

    def is_done(self):
        return self.ptr >= len(self.data)


def asset_info_from_script(b: bytes):
    reader = BytesReader(b)
    while not reader.is_done():
        try:
            op_code, _ = reader.read_script()
        except BytesReaderException as e:
            print(e)
            print(e.print_error())
            return None
        if op_code == 0xC0:
            break
    else:
        return None

    while not reader.is_done():
        for ch in ASSET_PREFIX:
            if reader.read_next_u8() != ch:
                break
        else:
            break
    else:
        return None

    asset_type = reader.read_next_u8()
    if asset_type == 111:
        # Owner
        return None

    asset_length = reader.read_next_u8()
    asset = reader.read(asset_length)
    reader.ptr += 8  # Satoshis

    if asset_type == 116:
        # Transfer
        if reader.can_read(35):  # Extra for OP_DROP
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    elif asset_type == 113:
        # Create
        reader.ptr += 2  # Divisions + Reissuable
        if reader.read(1) != b"\0":
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    elif asset_type == 114:
        # Reissue
        reader.ptr += 2  # Divisions + Reissuable
        if reader.can_read(35):
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    return None


def prev_block_hash_from_block(b: bytes):
    reader = BytesReader(b)
    reader.ptr += 4
    return reader.read(32)[::-1]


def asset_info_from_block(b: bytes):
    reader = BytesReader(b)
    reader.ptr += 68  # Version + Previous block hash + merkle root
    timestamp = int.from_bytes(reader.read(4), "little")
    reader.ptr += 4  # Bits

    if timestamp < KAWPOW_ACTIVATION_TIMESTAMP:
        reader.ptr += 4  # Nonce
    else:
        reader.ptr += 44  # Height + Nonce + Mix hash

    transaction_count = reader.read_var_int()
    for _ in range(transaction_count):
        has_witness = False
        reader.ptr += 4  # Version
        if reader.peek_next_u8() == 0:
            assert reader.read(2) == b"\x00\x01", "Not a witness flag"
            has_witness = True
        vin_count = reader.read_var_int()
        for _ in range(vin_count):
            reader.ptr += 36  # Previous txid + Previous idx
            script_length = reader.read_var_int()
            reader.read(script_length)
            reader.ptr += 4  # Sequence
        vout_count = reader.read_var_int()
        for _ in range(vout_count):
            reader.ptr += 8  # Satoshis
            script_length = reader.read_var_int()
            script = reader.read(script_length)
            asset_info = asset_info_from_script(script)
            if asset_info:
                yield asset_info

        if has_witness:
            for _ in range(vin_count):
                witness_count = reader.read_var_int()
                for _ in range(witness_count):
                    witness_length = reader.read_var_int()
                    reader.read(witness_length)
        reader.ptr += 4  # Locktime

    if not reader.is_done():
        raise BytesReaderException(reader.data, reader.ptr, "Leftover data")


class DaemonException(Exception):
    def __init__(self, status: int, message: bytes):
        self.status = status
        self.message = message

    def __repr__(self) -> str:
        return f"DemonException({self.status}, {self.message})"


class DaemonCommunicator:
    def __init__(self, url, port, username, password):
        self.daemon_url = f"http://{username}:{password}@{url}:{port}"
        self.id_counter = 0

    async def rpc_query(self, method: str, *params):
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.id_counter,
        }
        self.id_counter += 1
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.daemon_url, data=json.dumps(message).encode()
            ) as resp:
                if resp.status != 200:
                    raise DaemonException(resp.status, await resp.content.read())
                response = await resp.json()
                if response.get("error", None) is not None:
                    raise DaemonException(resp.status, response["error"])
                return response["result"]

    async def rest_query(self, path: str):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.daemon_url}/{path}") as resp:
                if resp.status != 200:
                    raise DaemonException(resp.status, await resp.content.read())
                return await resp.content.read()


class KuboCommunicator:
    def __init__(self, url, port):
        self.daemon_url = f"http://{url}:{port}"

    async def rpc_query(self, path: str, timeout=None):
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.daemon_url}/{path}",
                timeout=MAX_WAIT_SEC if timeout is None else timeout,
            ) as resp:
                if resp.status != 200:
                    raise DaemonException(resp.status, await resp.content.read())

                async for chunk, _ in resp.content.iter_chunks():
                    yield chunk

    async def _yield_data_from_ipfs(self, hash: str, seen: Optional[Set[str]] = None):
        if seen is None:
            seen = set()

        seen.add(hash)

        get_path = f"api/v0/cat?arg={hash}&length={MAX_DOWNLOAD_SIZE}"
        try:
            acc = bytearray()
            async for chunk in self.rpc_query(get_path, 0):
                acc.extend(chunk)
            yield acc

        except DaemonException as e:
            message = json.loads(e.message)["Message"]

            if message == "unexpected EOF":
                yield bytearray()
            elif message == "this dag node is a directory":
                ls_path = f"api/v0/ls?arg={hash}"

                acc = bytearray()
                async for chunk in self.rpc_query(ls_path, 0):
                    acc.extend(chunk)

                pb_node = json.loads(acc)
                for obj in pb_node["Objects"]:
                    ipfs = obj["Hash"]
                    if ipfs not in seen:
                        seen.add(ipfs)
                        async for chunk in self._yield_data_from_ipfs(ipfs, seen):
                            yield chunk
                    for link in obj["Links"]:
                        ipfs = link["Hash"]
                        if ipfs not in seen:
                            seen.add(ipfs)
                            async for chunk in self._yield_data_from_ipfs(ipfs, seen):
                                yield chunk
            else:
                raise e

    async def pin_hash(self, hash: str, height: int):
        adjacent_ipfs_hashes: Set[str] = set()

        pin_path = f"api/v0/pin/add?arg={hash}"
        try:
            async for _ in self.rpc_query(pin_path):
                pass

            async for chunk in self._yield_data_from_ipfs(hash):
                for maybe_match in CID_REGEX.finditer(chunk):
                    maybe_cid = maybe_match.group().decode()
                    try:
                        CID.decode(maybe_cid)
                        adjacent_ipfs_hashes.add(maybe_cid)
                    except Exception:
                        pass

        except Exception as e:
            if isinstance(e, DaemonException):
                error_message = json.loads(e.message)["Message"]
                for chunk in (
                    "path does not have enough components",
                    "pin: could not choose a decoder",
                ):
                    if chunk in error_message:
                        return None, hash, adjacent_ipfs_hashes, height
            if not isinstance(e, asyncio.TimeoutError):
                traceback.print_exc()
            return False, hash, adjacent_ipfs_hashes, height
        return True, hash, adjacent_ipfs_hashes, height

    async def ping(self):
        async for _ in self.rpc_query("api/v0/id"):
            break
        return True


def create_pin_task(
    ipfs_hash: str,
    pending_file_path: str,
    pending_set: Set[str],
    kubo: KuboCommunicator,
    height: int,
):
    if ipfs_hash in pending_set:
        return None
    add_ipfs_to_file(ipfs_hash, pending_file_path, pending_set)
    return asyncio.create_task(kubo.pin_hash(ipfs_hash, height))


def add_ipfs_to_file(ipfs_hash: str, file_path: str, associated_set: Set[str]):
    associated_set.add(ipfs_hash)
    with open(file_path, "w") as f:
        f.write("\n".join(associated_set))


def remove_ipfs_from_file(ipfs_hash: str, file_path: str, associated_set: Set[str]):
    associated_set.discard(ipfs_hash)
    with open(file_path, "w") as f:
        f.write("\n".join(associated_set))


async def get_block_for_height(daemon: DaemonCommunicator, height: int):
    try:
        block_hash = await daemon.rpc_query("getblockhash", height)
        raw_block = await daemon.rest_query(f"rest/block/{block_hash}.bin")
        return block_hash, raw_block
    except DaemonException as e:
        if e.status == 500:
            print("daemon work queue exceeded: try increasing the rpc work queue")
            return None
        error_code = json.loads(e.message)["error"]["code"]
        if error_code == -8:
            return None
        raise e


async def main():
    daemon_url = os.environ.get("DAEMON_URL", "127.0.0.1")
    daemon_port = os.environ.get("DAEMON_PORT", "8766")
    daemon_username = os.environ.get("DAEMON_USERNAME", None)
    if daemon_username is None:
        raise ValueError("No username supplied")
    daemon_password = os.environ.get("DAEMON_PASSWORD", None)
    if daemon_password is None:
        raise ValueError("No password supplied")

    kubo_url = os.environ.get("IPFS_URL", "127.0.0.1")
    kubo_port = os.environ.get("IPFS_PORT", "5001")

    directory = os.path.expanduser(os.environ.get("DIRECTORY", "~/.asset_pinner"))
    height_file = os.path.join(directory, "height.txt")
    missing_file = os.path.join(directory, "missing.txt")
    pending_file = os.path.join(directory, "pending.txt")

    if not os.path.exists(directory):
        os.mkdir(directory)

    if os.path.exists(height_file):
        with open(height_file, "r") as f:
            height = int(f.read())
    else:
        height = 0

    if os.path.exists(missing_file):
        with open(missing_file, "r") as f:
            missing_set = set(line.strip() for line in f.readlines())
    else:
        missing_set: Set[str] = set()
        with open(missing_file, "w") as f:
            f.write("")

    if os.path.exists(pending_file):
        with open(pending_file, "r") as f:
            pending_temp = set(line.strip() for line in f.readlines())

    else:
        pending_temp: Set[str] = set()
        with open(pending_file, "w") as f:
            f.write("")

    daemon = DaemonCommunicator(
        daemon_url, daemon_port, daemon_username, daemon_password
    )
    kubo = KuboCommunicator(kubo_url, kubo_port)

    curr_block_hash_hex = None

    running_tasks: Dict[
        str, asyncio.Task[Tuple[Optional[bool], str, Set[str], int]]
    ] = dict()
    block_tasks: Dict[int, asyncio.Task[Optional[Tuple[str, bytes]]]] = dict()
    missing_list: List[str] = list()

    pending_set: Set[str] = set()
    for pending_hash in pending_temp:
        if pending_hash not in running_tasks:
            task = create_pin_task(
                pending_hash, pending_file, pending_set, kubo, height
            )
            if task is not None:
                running_tasks[pending_hash] = task

    del pending_temp

    while True:
        if not missing_list:
            missing_list.extend(missing_set)
        await kubo.ping()

        try:
            chain_info = await daemon.rpc_query("getblockchaininfo")
        except DaemonException as e:
            if e.status == 401:
                print("Incorrect username/password")
                return
            code = json.loads(e.message)["error"]["code"]
            if code == -28:
                print("Waiting for block index")
                await asyncio.sleep(60)
                continue
            raise e
        daemon_height = chain_info["blocks"]

        completed_tasks = {
            hash: task for hash, task in running_tasks.items() if task.done()
        }
        for hash in completed_tasks.keys():
            running_tasks.pop(hash)

        if len(running_tasks) > MAX_TASK_SIZE:
            print("Waiting for tasks to complete (1)")
            while len(running_tasks) > (MAX_TASK_RESTART_PROPORTION * MAX_TASK_SIZE):
                await asyncio.wait(
                    running_tasks.values(), return_when=asyncio.FIRST_COMPLETED
                )

                hashes = set()
                for hash, task in running_tasks.items():
                    if task.done():
                        completed_tasks[hash] = task
                        hashes.add(hash)
                for hash in hashes:
                    running_tasks.pop(hash)

            print("Enough tasks have finished; continuing... (1)")

        while completed_tasks:
            task = completed_tasks.pop(next(k for k in completed_tasks.keys()))
            successful, ipfs_hash, adjacent_ipfs_hashes, attempt_height = task.result()
            if successful is None:
                # Malformed CID; just drop it
                remove_ipfs_from_file(ipfs_hash, pending_file, pending_set)
            elif not successful:
                if attempt_height > (daemon_height - MAX_BLOCKS_QUICK_RETRY):
                    # immediately try to re-pin
                    #
                    # Shouldn't be any duplicate keys due to our checks
                    pending_set.discard(ipfs_hash)
                    task = create_pin_task(
                        ipfs_hash, pending_file, pending_set, kubo, attempt_height
                    )
                    if task is not None:
                        running_tasks[ipfs_hash] = task
                else:
                    # add to missing
                    add_ipfs_to_file(ipfs_hash, missing_file, missing_set)
                    remove_ipfs_from_file(ipfs_hash, pending_file, pending_set)
            else:
                # remove from missing_file
                remove_ipfs_from_file(ipfs_hash, missing_file, missing_set)

                print(f"pinned: {ipfs_hash}")
                for adj_ipfs_hash in adjacent_ipfs_hashes:
                    if adj_ipfs_hash not in running_tasks:
                        task = create_pin_task(
                            adj_ipfs_hash,
                            pending_file,
                            pending_set,
                            kubo,
                            attempt_height,
                        )
                        if task is not None:
                            running_tasks[adj_ipfs_hash] = task

                            if len(running_tasks) > MAX_TASK_SIZE:
                                print("Waiting for tasks to complete (2)")
                                while len(running_tasks) > (
                                    MAX_TASK_RESTART_PROPORTION * MAX_TASK_SIZE
                                ):
                                    await asyncio.wait(
                                        running_tasks.values(),
                                        return_when=asyncio.FIRST_COMPLETED,
                                    )

                                    hashes = set()
                                    for hash, task in running_tasks.items():
                                        if task.done():
                                            completed_tasks[hash] = task
                                            hashes.add(hash)
                                    for hash in hashes:
                                        running_tasks.pop(hash)

                                print("Enough tasks have finished; continuing... (2)")

                remove_ipfs_from_file(ipfs_hash, pending_file, pending_set)
        try:
            for i in range(min(BLOCKS_TO_PREFETCH, daemon_height - height + 1)):
                get_height = height + i
                if get_height not in block_tasks:
                    block_tasks[get_height] = asyncio.create_task(
                        get_block_for_height(daemon, get_height)
                    )

            if height < daemon_height:
                task = block_tasks.pop(height)
                await task
                block = task.result()
                if block is None:
                    block = await get_block_for_height(daemon, height)
                    assert block
                block_hash, raw_block = block
                if curr_block_hash_hex is not None:
                    prev_hash = prev_block_hash_from_block(raw_block)
                    if prev_hash.hex() != curr_block_hash_hex:
                        print("reorg detected")
                        height = max(0, height - 61)
                        block_tasks.clear()
                        curr_block_hash_hex = None
                        continue

                for _, _, ipfs_hash in asset_info_from_block(raw_block):
                    if ipfs_hash not in running_tasks:
                        task = create_pin_task(
                            ipfs_hash, pending_file, pending_set, kubo, height
                        )
                        if task is not None:
                            running_tasks[ipfs_hash] = task

                with open(height_file, "w") as f:
                    f.write(str(height))
                height += 1
                curr_block_hash_hex = block_hash

            else:
                while missing_list and len(running_tasks) < (
                    RETRY_PROPORTION * MAX_TASK_SIZE
                ):
                    # Want to leave room for new blocks
                    ipfs_hash = missing_list.pop(0)
                    if ipfs_hash not in running_tasks:
                        task = create_pin_task(
                            ipfs_hash, pending_file, pending_set, kubo, -1
                        )
                        if task is not None:
                            running_tasks[ipfs_hash] = task

                await asyncio.sleep(10)
        except Exception:
            traceback.print_exc()
            print("sleeping for 10 minutes")
            await asyncio.sleep(60 * 10)


if __name__ == "__main__":
    asyncio.run(main())
