import uvloop
import struct
import socket
import asyncio
from collections import deque
from typing import Optional, Tuple, List

uvloop.install()


def parse_query(data: bytes) -> Tuple[int, List[bytes]]:
    header = data[:12]
    payload = data[12:]
    (
        transaction_id,
        flags,
        num_queries,
        num_answers,
        num_authority,
        num_additional
    ) = struct.unpack(">6H", header)

    queries: List[bytes] = []

    for i in range(num_queries):
        res = payload.index(0) + 5
        queries.append(payload[:res])
        payload = payload[res:]

    return transaction_id, queries


def get_domain(query: bytes) -> str:
    parts = []
    while True:
        length = query[0]
        query = query[1:]
        if length == 0:
            break
        parts.append(query[:length])
        query = query[length:]
    return "".join(x.decode("acsii") for x in parts)


def build_answer(
        trans_id: int, queryes: List[bytes], answer: Optional[bytes] = None, ttl: int = 128
) -> bytes:
    flags = 0
    flags |= 0x8000
    flags |= 0x0400

    if not answer:
        flags |= 0x0003

    header = struct.pack(
        ">6H", trans_id, flags, len(queryes), 1 if answer else 0, 0, 0
    )

    payload = b"".join(queryes)

    if answer:
        payload += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x70\x00\x04" + answer

    return header + payload


class DNSServer:

    def __init__(self, loop=asyncio.get_event_loop()):
        self.loop = loop
        self.sock = None
        self.event = asyncio.Event()
        self.queue = deque()
        self.subscribers = {}

    async def on_data_received(self, data: bytes, addr: Tuple[str, int]):
        trans_id, queryes = parse_query(data)

        for q in queryes:
            print(trans_id, get_domain(q))
            self.send(build_answer(trans_id, queryes), addr)

    def subscribe(self, fut: asyncio.Future) -> dict:
        self.subscribers[id(fut)] = fut
        return self.subscribers

    def futures(self, *args):
        for fut in args:
            asyncio.ensure_future(fut, loop=self.loop)

    def run(self, host: str = "0.0.0.0", port: int = 53):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        self.sock.bind((host, port))
        self.futures(self.recv_periodically(), self.send_periodically())

    async def sock_recv(
            self, fut: Optional[asyncio.Future], registered: bool = False
    ) -> asyncio.Future:

        fd = self.sock.fileno()

        if not fut:
            self.loop.create_future()

        if registered:
            self.loop.remove_reader(fd)

        try:
            data, addr = self.sock.recvfrom(2048)
        except (BlockingIOError, InterruptedError):
            self.loop.add_reader(fd, self.sock_recv, fut, True)
        except Exception as ex:
            print(ex)
            fut.set_result(0)
        else:
            fut.set_result((data, addr))
        return fut

    def recv_periodically(self):
        while True:
            data, addr = self.sock_recv()
            self.notify_subscribers(data, addr)

    def notify_subscribers(self, data: bytes, addr: Tuple[str, int]):
        self.futures(*(fut(data, addr) for fut in self.subscribers.values()))

    def sock_send(
            self, data: bytes,
            addr: Tuple[str, int],
            fut: Optional[asyncio.Future] = None,
            registered: bool = False
    ) -> Optional[asyncio.Future]:

        fd = self.sock.fileno()
        if not fut:
            fut = self.loop.create_future()
        if registered:
            self.loop.remove_writer(fd)
        if not data:
            return

    async def send_periodically(self):
        while True:
            await self.event.wait()
            try:
                while self.queue:
                    data, addr = self.queue.popleft()
                    _ = await self.sock.send(data, addr)
            finally:
                self.event.clear()


async def main(loop):
    dns = DNSServer(loop)
    dns.run()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
    loop.run_forever()
