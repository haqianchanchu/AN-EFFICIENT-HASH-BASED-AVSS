# coding=utf-8
import logging
import math
import asyncio
from GoSSamer.distribute.encode import (
    encode,
    decode,
    merkle_tree,
    get_merkle_branch,
    merkle_verify,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)



class AVIDMessageType:
    VAL = "VAL"
    ECHO = "ECHO"
    READY = "READY"
    RETRIEVE = "RETRIEVE"
    RESPONSE = "RESPONSE"


class AVID:
    # Class for Asynchronous Verifiable Information Dispersal
    def __init__(self, n, t, leader, recv, send, input_size, receiver_ids):
        """ Initialize the class with parameters:
        :param int n:  at least 3
        :param int f: fault tolerance, ``N >= 3f + 1``
        :param int leader: ``0 <= leader < N``
        :param recv: :func:`recv()` blocks until a message is
            recvd; message is of the form::
            (i, (tag, ...)) = recv()
            where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
        :param send: sends (without blocking) a message to a designated
            recipient ``send(i, (tag, ...))``
        :param input_size: the size of the input messages to be retrieved
        """
        # assert n >= 3 * t + 1, f"n: {n}, t: {t}"
        # assert t >= 0, f"t: {t}"
        # assert 0 <= leader < n, f"leader: {leader}, n: {n}"

        self._data = [None] * n
        self.n = n
        self.t = t
        self.leader = leader
        self.recv = recv
        self.send = send
        # size of input_list for disperse
        self.input_size = input_size
        # the response for retrieve
        self.retrieval_queue = asyncio.Queue()
        # the future value OK: retrive will be sent until ok is set
        self.ok_future = asyncio.Future()
        # queue of retrieval requests
        self.retrieval_requests = []
        self.receiver_ids = receiver_ids

    def broadcast(self, o):
        for i in self.receiver_ids:
            self.send(i, o)

    async def retrieve(self, sid, index):
        """ Retrieve individual item
        :param int index:  the index of retrieval
        """
        # we are able to retrieve things from AVID indivdually
        assert 0 <= index < self.input_size, f"index: {index}, input_size: {self.input_size}"

        # send retrieve after ok is set
        await self.ok_future

        # send retrieve to all the parties
        self.broadcast((sid, AVIDMessageType.RETRIEVE, index))
        logger.debug(f"Node-[{self.my_id}]: send AVIDMessageType.RETRIEVE to all")

        result = [None] * self.input_size
        response_set = set()

        # response threshold same as k
        response_threshold = self.t + 1

        while True:  # recv loop for retrieve
            sender, msg = await self.retrieval_queue.get()
            if msg[1] == AVIDMessageType.RESPONSE:
                (_, _, response_index, roothash, data) = msg
                # only retrieve the index we are currently retrieving
                if response_index != index:
                    continue

                if sender in response_set:
                    logger.warning(f"Node-[{self.my_id}]: Redundant RESPONSE from {sender}")
                    continue

                if not data:
                    logger.warning(f"Node-[{self.my_id}]: Received invalid RESPONSE from {sender}")
                    continue

                result[self.receiver_ids.index(sender)] = data
                response_set.add(sender)

                if len(response_set) >= response_threshold:
                    # decode the msg on enough response
                    decoded_output = ""
                    try:
                        decoded_output = decode(response_threshold, self.n, result)
                        # Rebuild the merkle tree to guarantee decoding is correct
                        _stripes = encode(response_threshold, self.n, decoded_output)
                        _mt = merkle_tree(_stripes)
                        _roothash = _mt[1]
                        if _roothash != roothash:
                            logger.error("Failed to verify merkle tree")
                    except Exception as e:
                        logger.error(f"Node-[{self.my_id}]: Failed to decode message: {e}")

                    logger.info(f"Node-[{self.my_id}]: RETRIEVE complete.")

                    return decoded_output

    async def disperse(self, sid, pid, input_list, client_mode=False):
        """ Main information dispersal handling
        :param int sid: e.x. tag to be used
        :param int pid: current member id
        :param int input_list: the list of message
            for each party from 1 to n from the dealer
        """
        # setup some parameters
        k = self.t + 1  # Wait to reconstruct.
        echo_threshold = math.ceil((self.n + self.t + 1) / 2)  # number of ECHOs needed
        ready_threshold = self.t + 1  # number of READYs needed for READY
        output_threshold = 2 * self.t + 1  # number of READYs needed for future OK
        self.my_id = pid
        # leader handling
        if pid == self.leader:
            # The leader erasure encodes the input, sending one strip to each participant
            assert len(input_list) == self.input_size, f"input_list length: {len(input_list)}, input_size: {self.input_size}"

            # construct the stripe list which contains the stripes for party 1 to party n
            stripes_list = [None] * self.input_size
            mt_list = [None] * self.input_size
            roothash_list = [None] * self.input_size
            for i, m in enumerate(input_list):
                logger.debug(f"Node-[{self.my_id}]: avid encode i={i}")  
                stripes_list[i] = encode(k, self.n, m)
                mt_list[i] = merkle_tree(stripes_list[i])
                roothash_list[i] = mt_list[i][1]

            # transpose for sending
            stripes_list_per_party = [list(i) for i in zip(*stripes_list)]
            for i in range(self.n):
                branch_list = [None] * self.input_size
                for j in range(self.input_size):
                    branch_list[j] = get_merkle_branch(i, mt_list[j])
                # send each person the column of stripes
                self.send(
                    self.receiver_ids[i],
                    (
                        sid,
                        AVIDMessageType.VAL,
                        roothash_list,
                        branch_list,
                        stripes_list_per_party[i],
                    ),
                )
                logger.debug(f"Node-[{self.my_id}]: send AVIDMessageType.VAL to {self.receiver_ids[i]}")
            if client_mode:
                return

        # counters and variables for msg
        echo_set = set()
        ready_set = set()
        ready_sent = False
        from_leader = None
        # internal storage
        my_stripes = None
        my_roothash_list = None

        while True:  # main recv loop
            sender, msg = await self.recv()
            logger.debug(f"Node-[{self.my_id}]: receive msg from {sender}")

            if msg[1] == AVIDMessageType.VAL and from_leader is None:
                # Validation
                (_, _, roothash_list, branch_list, stripes_for_each) = msg
                
                if sender != self.leader:
                    logger.warning(f"Node-[{self.my_id}]: VAL message from other than leader: {sender}")
                    continue

                # merkle tree verification
                validation_fail_flag = False
                for i in range(len(stripes_for_each)):
                    # verify each entry in the stripes
                    if not merkle_verify(
                        self.n,
                        stripes_for_each[i],
                        roothash_list[i],
                        branch_list[i],
                        self.receiver_ids.index(pid),
                    ):
                        logger.error(f"Node-[{self.my_id}]: Failed to validate VAL message")
                        validation_fail_flag = True
                        break
                if validation_fail_flag:
                    continue

                logger.debug(f"Node-[{self.my_id}]: validate VAL message success")

                # Update and store the stripes & roothashes for retrieve
                from_leader = pid
                my_stripes = stripes_for_each
                my_roothash_list = roothash_list

                # echo others
                self.broadcast((sid, AVIDMessageType.ECHO))

            elif msg[1] == AVIDMessageType.ECHO:
                logger.debug(f"Node-[{self.my_id}]: receive AVIDMessageType.ECHO message from {sender}")
                # Validation
                if sender in echo_set:
                    logger.warning(f"Node-[{self.my_id}]: Redundant ECHO")
                    continue
                # Update
                echo_set.add(sender)

            elif msg[1] == AVIDMessageType.READY:
                # Validation
                if sender in ready_set:
                    logger.warning(f"Node-[{self.my_id}]: Redundant READY")
                    continue
                # Update
                ready_set.add(sender)

            elif msg[1] == AVIDMessageType.RETRIEVE:
                _, _, index = msg
                # send the response sender requested
                if not self.ok_future.done() or my_stripes is None:
                    # enqueue a retrieve request
                    # READY may precede this node's VAL on another channel.
                    # Retain the request until both readiness and data exist.
                    self.retrieval_requests.append((sender, index))
                elif self.ok_future.done():
                    logger.debug(f"Node-[{self.my_id}]: send AVIDMessageType.RESPONSE to {sender}, index = {index}, len(my_roothash_list) = {len(my_roothash_list)}, tag = {sid}")
                    self.send(
                        sender,
                        (
                            sid,
                            AVIDMessageType.RESPONSE,
                            index,
                            my_roothash_list[index],
                            my_stripes[index],
                        ),
                    )

            elif msg[1] == AVIDMessageType.RESPONSE:
                # put in the queue for retrieve
                self.retrieval_queue.put_nowait((sender, msg))

            if len(echo_set) >= echo_threshold and not ready_sent:
                logger.debug(f"Node-[{self.my_id}]: receive enough echo")
                ready_sent = True
                self.broadcast((sid, AVIDMessageType.READY))

            # Amplify ready messages
            if len(ready_set) >= ready_threshold and not ready_sent:
                logger.debug(f"Node-[{self.my_id}]: receive {ready_threshold} ready and not ready_sent")
                ready_sent = True
                self.broadcast((sid, AVIDMessageType.READY))
                logger.debug(f"Node-[{self.my_id}]: send AVIDMessageType.READY to all")

            if len(ready_set) >= output_threshold and len(echo_set) >= k:
                # update ok future indicating ready for retrieve
                logger.debug(f"Node-[{self.my_id}]: receive {output_threshold} ready and {len(echo_set)} echo")
                if not self.ok_future.done():
                    self.ok_future.set_result(True)

            # Handle deferred requests
            if self.ok_future.done() and my_stripes is not None and len(self.retrieval_requests) > 0:
                for (sender, index) in self.retrieval_requests:
                    logger.debug(f"Node-[{self.my_id}]: Sending deferred response sender:{sender} index:{index}")
                    self.send(
                        sender,
                        (
                            sid,
                            AVIDMessageType.RESPONSE,
                            index,
                            my_roothash_list[index],
                            my_stripes[index],
                        ),
                    )
                self.retrieval_requests.clear()
