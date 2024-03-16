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
KAWPOW_ACTIVATION_TIMESTAMP = 1585159200
ASSET_PREFIX = b"rvn"
MAX_TASK_SIZE = 100
MAX_WAIT_SEC = 20 * 60
MAX_DOWNLOAD_SIZE = 1024 * 1024
WINDOW_SIZE = 128
CID_REGEX = re.compile(
    rb"Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[A-Za-z2-7]{58,}|B[A-Z2-7]{58,}|z[1-9A-HJ-NP-Za-km-z]{48,}|F[0-9A-F]{50,}"
)
MAX_BLOCKS_RETRY = 60 * 2  # 2 hours
MAX_MISSING_TO_RETRY = 5
BLOCKS_TO_PREFETCH = 20
NAME_SEPERATOR = "()"


class BytesReaderException(Exception):
    pass


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
        assert self.ptr >= 0, self.ptr
        if self.ptr >= len(self.data):
            raise BytesReaderException("Out of bounds")
        val = self.data[self.ptr]
        self.ptr += 1
        return val

    def read(self, i: int):
        if (self.ptr + i) > len(self.data):
            raise BytesReaderException("Out of bounds")
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
        op_code, _ = reader.read_script()
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
    reader.read(8)  # Satoshis

    if asset_type == 116:
        # Transfer
        if reader.can_read(35):  # Extra for OP_DROP
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    elif asset_type == 113:
        # Create
        reader.read(1)  # Divisions
        reader.read(1)  # Reissuable
        if reader.read(1) != b"\0":
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    elif asset_type == 114:
        # Reissue
        reader.read(1)  # Divisions
        reader.read(1)  # Reissuable
        if reader.can_read(35):
            ipfs_hash = reader.read(34)
            if ipfs_hash[:2] == b"\x12\x20":
                return asset.decode(), asset_type, base58.b58encode(ipfs_hash).decode()
    return None


def prev_block_hash_from_block(b: bytes):
    reader = BytesReader(b)
    reader.read(4)
    return reader.read(32)[::-1]


def asset_info_from_block(b: bytes):
    reader = BytesReader(b)
    reader.read(4)  # Version
    reader.read(32)  # Previous block hash
    reader.read(32)  # Merkle root
    timestamp = int.from_bytes(reader.read(4), "little")
    reader.read(4).hex()  # Bits

    if timestamp < KAWPOW_ACTIVATION_TIMESTAMP:
        reader.read(4)  # Nonce
    else:
        reader.read(4)  # Height
        reader.read(8)  # Nonce
        reader.read(32)  # Mix hash

    transaction_count = reader.read_var_int()
    for _ in range(transaction_count):
        has_witness = False
        reader.read(4)  # Version
        if reader.peek_next_u8() == 0:
            assert reader.read(2) == b"\x00\x01", "Not a witness flag"
            has_witness = True
        vin_count = reader.read_var_int()
        for _ in range(vin_count):
            reader.read(32)  # Previous txid
            reader.read(4)  # Previous idx
            script_length = reader.read_var_int()
            reader.read(script_length)
            reader.read(4)  # Sequence
        vout_count = reader.read_var_int()
        for _ in range(vout_count):
            reader.read(8)  # Satoshis
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
        reader.read(4)  # Locktime

    if not reader.is_done():
        raise BytesReaderException("Leftover data")


class DaemonException(Exception):
    def __init__(self, status, message):
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

    async def _walk_hash(self, hash: str, seen=None):
        if seen is None:
            seen = set()

        get_path = f"api/v0/cat?arg={hash}&length={MAX_DOWNLOAD_SIZE}"
        try:
            async for chunk in self.rpc_query(get_path, 0):
                yield chunk
        except DaemonException as e:
            message = json.loads(e.message)["Message"]

            if message == "unexpected EOF":
                yield b""
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
                        async for chunk in self._walk_hash(ipfs, seen):
                            yield chunk
                    for link in obj["Links"]:
                        ipfs = link["Hash"]
                        if ipfs not in seen:
                            seen.add(ipfs)
                            async for chunk in self._walk_hash(ipfs, seen):
                                yield chunk
            else:
                raise e

    async def pin_hash(self, hash: str, name: str):
        adjacent_ipfs_hashes: Set[str] = set()

        pin_path = f"api/v0/pin/add?arg={hash}&name={name}"
        try:
            async for _ in self.rpc_query(pin_path):
                pass

            window = bytearray()
            async for chunk in self._walk_hash(hash):
                chunk = bytearray(chunk)
                while len(window) < WINDOW_SIZE and len(chunk) > 0:
                    window.append(chunk.pop(0))
                while len(window) == WINDOW_SIZE and len(chunk) > 0:
                    maybe_match = CID_REGEX.search(window)
                    if maybe_match:
                        maybe_cid = maybe_match.group().decode()
                        try:
                            CID.decode(maybe_cid)
                            adjacent_ipfs_hashes.add(maybe_cid)
                        except Exception:
                            pass
                    window.pop(0)
                    window.append(chunk.pop(0))

        except Exception as e:
            if not isinstance(e, asyncio.TimeoutError):
                traceback.print_exc()
            return False, hash, name, adjacent_ipfs_hashes
        return True, hash, name, adjacent_ipfs_hashes

    async def ping(self):
        async for _ in self.rpc_query("api/v0/id"):
            break
        return True


def create_pin_task(
    ipfs_hash: str, name: str, pending_file_path: str, kubo: KuboCommunicator
):
    add_name_to_file(name, ipfs_hash, pending_file_path)
    return asyncio.create_task(kubo.pin_hash(ipfs_hash, name))


def add_name_to_file(name: str, ipfs_hash: str, file_path: str):
    with open(file_path, "r") as f:
        missing = dict(line.strip().split(" ") for line in f.readlines())
    missing[name] = ipfs_hash
    with open(file_path, "w") as f:
        f.write("\n".join(f"{name} {ipfs_hash}" for name, ipfs_hash in missing.items()))


def remove_name_from_file(name: str, file_path):
    with open(file_path, "r") as f:
        missing = dict(line.strip().split(" ") for line in f.readlines())
    missing.pop(name, None)
    with open(file_path, "w") as f:
        f.write("\n".join(f"{name} {ipfs_hash}" for name, ipfs_hash in missing.items()))


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
            missing = dict(line.strip().split(" ") for line in f.readlines())
    else:
        missing: Dict[str, str] = dict()
        with open(missing_file, "w") as f:
            f.write("")

    missing_list: List[Tuple[str, str]] = list()
    if os.path.exists(pending_file):
        with open(pending_file, "r") as f:
            for line in f.readlines():
                name, ipfs_hash = line.strip().split(" ")
                missing_list.append((name, ipfs_hash))
    else:
        with open(pending_file, "w") as f:
            f.write("")

    daemon = DaemonCommunicator(
        daemon_url, daemon_port, daemon_username, daemon_password
    )

    kubo = KuboCommunicator(kubo_url, kubo_port)

    curr_block_hash_hex = None

    running_tasks: Set[asyncio.Task[Tuple[bool, str, str, Set[str]]]] = set()
    waiting_message_flag = False

    block_tasks: Dict[int, asyncio.Task[Optional[Tuple[str, bytes]]]] = dict()

    while True:
        if not missing_list:
            missing_list.extend(missing.items())
        await kubo.ping()
        completed_tasks = {task for task in running_tasks if task.done()}
        running_tasks.difference_update(completed_tasks)

        while len(running_tasks) > MAX_TASK_SIZE:
            if not waiting_message_flag:
                waiting_message_flag = True
                print("Waiting for tasks to complete")
            complete, pending = await asyncio.wait(
                running_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            running_tasks = pending
            completed_tasks.update(complete)

        if waiting_message_flag:
            waiting_message_flag = False
            print("Enough tasks have finished; continuing...")

        for task in completed_tasks:
            successful, ipfs_hash, name, adjacent_ipfs_hashes = task.result()
            remove_name_from_file(name, pending_file)
            if not successful:
                _, created_height, _, _ = name.split(NAME_SEPERATOR)
                if int(created_height) > (height - MAX_BLOCKS_RETRY):
                    # immediately try to re-pin
                    task = create_pin_task(ipfs_hash, name, pending_file, kubo)
                    running_tasks.add(task)
                else:
                    # add to missing
                    missing[ipfs_hash] = name
                    add_name_to_file(ipfs_hash, name, missing_file)

            else:
                # remove from missing_file
                remove_name_from_file(ipfs_hash, missing_file)

                for ipfs_hash in adjacent_ipfs_hashes:
                    name = name.split(NAME_SEPERATOR)
                    name[-1] = "link"
                    name = NAME_SEPERATOR.join(name)
                    task = create_pin_task(ipfs_hash, name, pending_file, kubo)
                    running_tasks.add(task)
        try:
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

            for i in range(min(BLOCKS_TO_PREFETCH, daemon_height - height + 1)):
                get_height = height + i
                if get_height not in block_tasks:
                    block_tasks[get_height] = asyncio.create_task(
                        get_block_for_height(daemon, get_height)
                    )

            if height <= daemon_height:
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
                        continue

                for asset, asset_type, ipfs_hash in asset_info_from_block(raw_block):
                    task = create_pin_task(
                        ipfs_hash,
                        f"{asset}{NAME_SEPERATOR}{height:09}{NAME_SEPERATOR}{chr(asset_type)}{NAME_SEPERATOR}root",
                        pending_file,
                        kubo,
                    )

                    running_tasks.add(task)

                with open(height_file, "w") as f:
                    f.write(str(height))
                height += 1
                curr_block_hash_hex = block_hash

            else:
                count = 0
                while missing_list:
                    count += 1
                    if count >= MAX_MISSING_TO_RETRY:
                        break
                    name, ipfs_hash = missing_list.pop(0)
                    task = create_pin_task(ipfs_hash, name, pending_file, kubo)
                    running_tasks.add(task)
                await asyncio.sleep(60)
        except Exception:
            traceback.print_exc()
            print("sleeping for 10 minutes")
            await asyncio.sleep(60 * 10)


if __name__ == "__main__":
    asyncio.run(main())
