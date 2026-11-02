import argparse
import asyncio
import json
import os
import sys
from datetime import datetime

from bleak import BleakClient, BleakScanner

UUID_SERVICE = "7e400001-b5a3-f393-e0a9-e50e24dcca9d"
UUID_WRITE = "7e400002-b5a3-f393-e0a9-e50e24dcca9d"
UUID_NOTIFY = "7e400003-b5a3-f393-e0a9-e50e24dcca9d"
UUID_BATTERY = "00002a19-0000-1000-8000-00805f9b34fb"

VERBOSE = False

def log_debug(mac: str, msg: str):
    if VERBOSE:
        print(f"[{datetime.now().isoformat()}] [{mac}] {msg}", file=sys.stderr)

def to_hex(buf: bytes) -> str:
    h = " ".join(f"{b:02X}" for b in buf)
    return h[:96] + "..." if len(h) > 96 else h

def get_jpg_size(data: bytes) -> tuple[int, int]:
    i = 2
    while i < len(data) - 8:
        while data[i] == 0xFF:
            i += 1
        m, sz = data[i], int.from_bytes(data[i+1:i+3], "big")
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            return int.from_bytes(data[i+6:i+8], "big"), int.from_bytes(data[i+4:i+6], "big")
        i += sz + 1
    return 0, 0

class BadgeSession:
    def __init__(self, mac: str):
        self.mac = mac
        self.client = BleakClient(mac)
        self.futures: dict[str, asyncio.Future] = {}
        self.chunk_fut: asyncio.Future | None = None
        self.chunk_exp = 0
        self.max_block_size = 0

    async def __aenter__(self):
        log_debug(self.mac, "Connecting...")
        await self.client.connect()
        await self.client.start_notify(UUID_NOTIFY, self._notify)
        log_debug(self.mac, "Connected. Starting initialization...")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.client.disconnect()
        log_debug(self.mac, "Badge disconnected.")

    def _notify(self, sender, data: bytearray):
        if not data:
            return
        log_debug(self.mac, f"[RX] {to_hex(data)}")
        match data[0]:
            case 0xDC:
                if len(data) < 8:
                    return
                key = f"ack_{data[3]}_{data[4]}"
                if key not in self.futures or self.futures[key].done():
                    return
                if data[7] == 1:
                    self.futures[key].set_result(None)
                else:
                    self.futures[key].set_exception(RuntimeError(f"ACK Error: {data[7]}"))
                return

            case 0xCD:
                if len(data) < 8:
                    return
                flen = (data[1] << 8) | data[2]
                plen = (data[6] << 8) | data[7]
                if flen != plen + 5 or len(data) < 8 + plen:
                    return
                cls, sub = data[3], data[5]
                payload = bytes(data[8:8 + plen])
                ack_frame = bytes([0xDC, 0, 5, cls, sub, (flen + 3) >> 8, (flen + 3) & 0xFF, 1])

                asyncio.create_task(self._write(ack_frame))

                key = f"data_{cls}_{sub}"
                if key in self.futures and not self.futures[key].done():
                    self.futures[key].set_result(payload)

                if cls != 0x20 or sub != 0x01 or not self.chunk_fut or self.chunk_fut.done():
                    return
                if len(payload) >= 4:
                    code = int.from_bytes(payload[:4], "big")
                    if code == self.chunk_exp:
                        self.chunk_fut.set_result(None)
                    else:
                        self.chunk_fut.set_exception(RuntimeError(f"Transfer Rejected: Code {code}"))

    async def _write(self, data: bytes):
        log_debug(self.mac, f"[TX] {to_hex(data)}")
        for i in range(0, len(data), 487):
            await self.client.write_gatt_char(UUID_WRITE, data[i:i + 487], response=False)

    def _build(self, cls: int, sub: int | None, payload: bytes) -> bytes:
        if sub is None:
            return bytes([0xCD, 0, 2, cls, 1])
        length = 5 + len(payload)
        return bytes([0xCD, length >> 8, length & 0xFF, cls, 1, sub, len(payload) >> 8, len(payload) & 0xFF]) + payload

    async def _wait(self, prefix: str, cls: int, sub: int, timeout: float):
        key = f"{prefix}_{cls}_{sub}"
        self.futures[key] = asyncio.get_running_loop().create_future()
        try:
            return await asyncio.wait_for(self.futures[key], timeout)
        finally:
            self.futures.pop(key, None)

    async def send_cmd(self, cls: int, sub: int, payload: bytes = b""):
        f = asyncio.create_task(self._wait("ack", cls, sub, 3.0))
        await self._write(self._build(cls, sub, payload))
        await f

    async def req_data(self, cls: int, sub: int, payload: bytes = b"") -> bytes:
        f_data = asyncio.create_task(self._wait("data", cls, sub, 5.0))
        await self._write(self._build(cls, sub, payload))
        if cls != 0x20:
            try:
                await asyncio.wait_for(self._wait("ack", cls, sub, 3.0), timeout=3.0)
            except asyncio.TimeoutError:
                pass
        return await f_data

    async def wait_chunk(self, code: int, timeout: float = 10.0):
        self.chunk_exp = code
        self.chunk_fut = asyncio.get_running_loop().create_future()
        try:
            await asyncio.wait_for(self.chunk_fut, timeout)
        finally:
            self.chunk_fut = None

    async def init_seq(self) -> tuple[str, str, int, int, int, int]:
        now = datetime.now()
        p = ((max(0, now.year - 2000) & 0x3F) << 26) | ((now.month & 0x0F) << 22) | ((now.day & 0x1F) << 17) | ((now.hour & 0x1F) << 12) | ((now.minute & 0x3F) << 6) | (now.second & 0x3F)

        await self.send_cmd(0x12, 0x01, p.to_bytes(4, "big"))

        mac_b = await self.req_data(0x1A, 0x0A)
        rmac = ":".join(f"{b:02X}" for b in mac_b)

        name_b = await self.req_data(0x1A, 0x0C)
        name = name_b[1:].decode(errors="ignore") if len(name_b) > 1 else ""

        ctrl = await self.req_data(0x20, 0x02)
        w, h = 0, 0
        if len(ctrl) >= 32 and ctrl[0] == 0x01:
            w = (ctrl[2] << 8) | ctrl[3]
            h = (ctrl[4] << 8) | ctrl[5]
            self.max_block_size = (ctrl[30] << 8) | ctrl[31]
            p1_len = ctrl[6] if len(ctrl) > 6 else 0
            p1 = ctrl[7:7+p1_len].decode(errors='ignore') if p1_len else ""
            p2_start = 7 + p1_len
            p2_len = ctrl[p2_start] if len(ctrl) > p2_start else 0
            p2 = ctrl[p2_start+1:p2_start+1+p2_len].decode(errors='ignore') if p2_len else ""
            p3_start = p2_start + 1 + p2_len + 5
            p3_len = ctrl[p3_start] if len(ctrl) > p3_start else 0
            p3 = ctrl[p3_start+1:p3_start+1+p3_len].decode(errors='ignore') if p3_len else ""
            log_debug(self.mac, f"[Device Info] Screen: {w}x{h}, MaxBlockSize: {self.max_block_size}, Cap: {p1}, {p2}, {p3}")

        store = await self.req_data(0x20, 0x04)
        free = int.from_bytes(store[4:8], "big") // 1024 if len(store) >= 8 else 0

        try:
            bat_b = await self.client.read_gatt_char(UUID_BATTERY)
            bat = bat_b[0]
        except Exception:
            bat = -1

        log_debug(self.mac, "Initialization sequence completed.")
        return name, rmac, w, h, free, bat

    async def send_file(self, data: bytes):
        size = len(data)
        if size > self.max_block_size * 24 - 4:
            raise ValueError("File too large")

        blocks = []
        offset = 0
        bid = 1
        while offset < size:
            length = min(size - offset, (self.max_block_size - 4) if bid == 1 else self.max_block_size)
            blocks.append(data[offset:offset + length])
            offset += length
            bid += 1

        sid = os.urandom(4)
        dsize = size + 4
        init_p = sid + b"\x02\x08\x00\x00\x00" + dsize.to_bytes(4, "big") + b"\x00\x00\x00\x00"

        log_debug(self.mac, f"Initiating file transfer. Size: {size}")
        await self._write(self._build(0x1F, 2, init_p))
        await self.wait_chunk(1000)

        sum8 = 0
        cs32 = sum(size.to_bytes(4, "big"))

        for k, blk in enumerate(blocks, 1):
            log_debug(self.mac, f"Sending chunk {k}/{len(blocks)}")
            is_first = k == 1
            hend = 14 if is_first else 10
            flen = 5 + (hend - 8) + len(blk) + 4

            frame = bytearray([0xCD, flen >> 8, flen & 0xFF, 0x1F, 1, 1, (flen - 5) >> 8, (flen - 5) & 0xFF, k >> 8, k & 0xFF])
            if is_first:
                frame.extend(size.to_bytes(4, "big"))
            frame.extend(blk)

            bcs = sum(blk)
            sum8 = (sum8 + bcs) & 0xFFFFFFFF
            tval = (bcs + cs32 + 1) if is_first else (bcs + k)
            frame.extend(tval.to_bytes(4, "big"))

            await self._write(bytes(frame))
            await self.wait_chunk(1000 + k)

        vcs = (sum8 + cs32) & 0xFFFFFFFF
        await self._write(self._build(0x1F, 3, vcs.to_bytes(4, "big")))
        await self.wait_chunk(2)
        log_debug(self.mac, "Upload complete. Checking free space...")
        await self.req_data(0x20, 0x04)

async def do_scan(fetch_info: bool, target_macs: list[str] | None = None):
    results = {}

    if target_macs:
        for mac in target_macs:
            results[mac] = {"name": "", "rssi": None}
    else:
        timeout_sec = 5.0
        print(f"Scanning for Web Badges ({timeout_sec}s)...", file=sys.stderr)
        devices = await BleakScanner.discover(timeout=timeout_sec, return_adv=True)
        for d, adv in devices.values():
            if UUID_SERVICE in adv.service_uuids:
                results[d.address] = {
                    "name": adv.local_name or d.name or "",
                    "rssi": adv.rssi
                }

        if not results:
            print("No badges found.", file=sys.stderr)
            print(json.dumps({}, indent=2))
            return

    if fetch_info:
        async def fetch(mac: str):
            print(f"Fetching details for {mac}...", file=sys.stderr)
            try:
                async with BadgeSession(mac) as session:
                    name, rmac, w, h, free, bat = await session.init_seq()
                    results[mac].update({
                        "name": name or results[mac]["name"],
                        "battery": bat if bat >= 0 else None,
                        "width": w,
                        "height": h,
                        "storageKiB": free
                    })
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log_debug(mac, f"Init Error: {e}")
                print(f"[{mac}] Failed to fetch info", file=sys.stderr)
                results[mac].update({
                    "battery": None,
                    "width": None,
                    "height": None,
                    "storageKiB": None
                })

        for m in results:
            await fetch(m)

    sorted_results = {k: results[k] for k in sorted(results.keys())}
    print(json.dumps(sorted_results, indent=2))

async def run_cmd(macs: list[str], func, *args):
    async def wrap(mac: str):
        try:
            async with BadgeSession(mac) as session:
                await session.init_seq()
                await func(session, *args)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[{mac}] Failed:", e, file=sys.stderr)

    for m in macs:
        await wrap(m)

async def do_upload(macs: list[str], files: list[str]):
    async def wrap(mac: str, path: str):
        try:
            with open(path, "rb") as f:
                data = f.read()
            jw, jh = get_jpg_size(data)
            async with BadgeSession(mac) as session:
                _, _, w, h, _, _ = await session.init_seq()
                if not session.max_block_size:
                    raise ValueError("Badge block size is unknown. Cannot upload.")
                if (jw, jh) != (0, 0) and (jw, jh) != (w, h):
                    raise ValueError(f"Resolution mismatch (Image: {jw}x{jh}px, Badge: {w}x{h}px)")
                await session.send_file(data)
            print(f"[{mac}] Uploaded {path}", file=sys.stderr)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[{mac}] Failed:", e, file=sys.stderr)

    for m, f in zip(macs, files):
        await wrap(m, f)

def main():
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--lang", choices=["en", "ja"], help="Set badge language")
    group.add_argument("-c", "--call", action="store_true", help="Send call alert")
    group.add_argument("-f", "--fetch", action="store_true", help="Fetch detailed device information")
    group.add_argument("-u", "--upload", action="store_true", help="Upload media file (format: MAC=FILE)")
    parser.add_argument("targets", nargs="*", metavar="TARGET")
    args = parser.parse_args()

    VERBOSE = args.verbose

    try:
        if not any([args.lang, args.call, args.fetch, args.upload]):
            if args.targets:
                parser.error("Targets specified without an action (-l, -c, -f, -u)")
            asyncio.run(do_scan(fetch_info=False))
            return

        if args.fetch:
            asyncio.run(do_scan(fetch_info=True, target_macs=args.targets))
            return

        if not args.targets:
            parser.error("At least one target is required for this action")

        if args.lang:
            val = 1 if args.lang == "en" else 8
            asyncio.run(run_cmd(args.targets, lambda s: s.send_cmd(0x12, 0x15, bytes([val]))))
            return

        if args.call:
            asyncio.run(run_cmd(args.targets, lambda s: s.send_cmd(0x12, 0x0B, bytes([1]))))
            return

        macs, files = [], []
        for t in args.targets:
            parts = t.split("=", 1)
            if len(parts) != 2:
                parser.error(f"Invalid target for -u (expected MAC=FILE): {t}")
            macs.append(parts[0])
            files.append(parts[1])

        asyncio.run(do_upload(macs, files))

    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)

if __name__ == "__main__":
    main()
