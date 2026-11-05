import logging
import time
from pytest import mark
from random import randint
from GoSSamer.crypto.polynomial import polynomials_over
from hbacss.backup.hbacss import Hbacss0
from GoSSamer.util.misc import print_exception_callback
from hbacss.poly_commit_const_hat import PolyCommitConst, gen_pc_const_crs

import asyncio

import logging
logger = logging.getLogger(__name__)
# logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
logger.setLevel(logging.INFO)


def get_avss_params(ids, t):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g = G1.rand()
    h = G1.rand()
    n = len(ids)

    private_keys = [ZR.rand() for i in range(n)]
    public_keys = {ids[i]:g ** private_keys[i] for i in range(n)}
    return g, h, public_keys, private_keys


@mark.asyncio
async def test_acss_dcr(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1
    ids = list(range(n))

    g, h, pks, sks = get_avss_params(ids, t)
    alpha = ZR.random()
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    pc = PolyCommitConst(crs)
    sends, recvs, _ = test_router(2*n)
    batchsize = 4

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    avss_tasks = [None] * n
    dealer_id = ids[randint(0, n - 1)]

    hbavss_list = [None] * n
    for i in range(n):
        hbavss = Hbacss0(pks, sks[i], g, h, ids, t, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc, client_mode=False)
        hbavss_list[i] = hbavss
        if ids[i] == dealer_id:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=(secrets, secrets_hat)))
        else:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    outputs = await asyncio.gather(
        *[hbavss_list[i].output_queue.get() for i in range(n)]
    )
    shares = [output[2] for output in outputs]
    for task in avss_tasks:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in ids), item))
        )

    assert recovered_values == secrets

@mark.asyncio
async def test_acss_dcr_external_dealer(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1
    d = t
    ids = list(range(1, n+1))
    

    g, h, pks, sks = get_avss_params(ids, t)
    alpha = ZR.random()
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    pc = PolyCommitConst(crs)
    sends, recvs, _ = test_router(2*n)
    batchsize = 8

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    avss_tasks = [None] * n
    dealer_id = n+3

    hbavss_list = [None] * n

    start_time = time.time()
    
    for i in range(n):
        hbavss = Hbacss0(pks, sks[i], g, h, ids, t, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc, client_mode=True)
        hbavss_list[i] = hbavss
        avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    
    dealeracss = Hbacss0(pks, sks[i], g, h, ids, t, dealer_id, G1, ZR, sends[dealer_id], recvs[dealer_id], pc, client_mode=True)
    dealertask = asyncio.create_task(dealeracss.avss(0, values=(secrets, secrets_hat)))
    
    outputs = await asyncio.gather(
        *[hbavss_list[i].output_queue.get() for i in range(n)]
    )
    end_time = time.time()
    print(f"Time taken to get AVSS outputs: {end_time - start_time} seconds")
    
    shares = [output[2] for output in outputs]
    for task in avss_tasks + [dealertask]:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in ids), item))
        )

    assert recovered_values == secrets