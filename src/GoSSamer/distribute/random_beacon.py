import asyncio
from collections import defaultdict
from random import randint
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RandomBeacon:
    def __init__(self, threshold, receiver_ids, send, recv, field):
        """
        :param threshold: int, t
        :param receiver_ids: list of int, ids to send randomness to
        :param send: callable (dst_id, msg)
        :param recv: awaitable, returns (src_id, message)
        :param field: finite field instance with `.random()` method
        """
        self.threshold = threshold
        self.receiver_ids = receiver_ids
        self.send = send
        self.recv = recv
        self.field = field

        self.session_counts = defaultdict(set)  # sid -> set of sender ids
        self.waiters = defaultdict(list)        # sid -> list of asyncio.Future

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def run(self):
        logger.debug(f"beacon dealer running")
        while True:
            sender, msg = await self.recv()
            sid = msg[0]

            logger.debug(f"beacon dealer receive request from sender = {sender}, sid = {sid}")
            
            self.session_counts[sid].add(sender)

            if len(self.session_counts[sid]) == self.threshold + 1:
                rnd = self.field.random()

                # Broadcast to all receiver ids
                for rid in self.receiver_ids:
                    logger.debug(f"beacon dealer receive request from sender = {sender}, sid = {sid}")
                    self.send(rid, (sid, rnd))

                # Notify all local waiters
                for fut in self.waiters[sid]:
                    if not fut.done():
                        fut.set_result(rnd)

    async def request(self, sid):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self.waiters[sid].append(fut)

        # Send your request (assume caller will handle own ID)
        self.send("beacon", sid)  # or a specific beacon_id if needed

        return await fut
