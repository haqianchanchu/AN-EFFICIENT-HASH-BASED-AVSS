"""CHECKED and BATCH validation over the reference reliable broadcast."""
import pickle

from GoSSamer.distribute.optqrbc import optqrbc
from GoSSamer.util.misc import wrap_send


async def broadcast(sid, parameters, node, kind, leader, input_future, *, send, subscribe, events):
    async def valid(value):
        if kind == 'CHECKED':
            return isinstance(value, bytes) and len(value) == 32
        try:
            digest, targets = pickle.loads(value)
            return (isinstance(digest, bytes) and len(digest) == 32
                    and isinstance(targets, tuple) and 0 < len(targets) <= parameters.t
                    and targets == tuple(sorted(set(targets)))
                    and all(type(k) is int and 0 <= k < parameters.n for k in targets))
        except Exception:
            return False

    tag = (kind, leader)
    payload = await input_future if node == leader else None
    await optqrbc((sid, kind, leader), node, list(range(parameters.n)), parameters.t,
                 leader, valid, payload, lambda value: events.put_nowait((kind, leader, value)),
                 wrap_send(tag, send), subscribe(tag))
