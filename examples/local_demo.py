"""Four-party in-memory sharing and reconstruction example."""
import asyncio
from pypairing import ZR
from adkg.router import SimpleRouter
from bdecs_avss.bdecs import Parameters
from bdecs_avss.protocol import AVSS

async def main():
    router = SimpleRouter(4)
    nodes = [AVSS(Parameters(4, 1, 1), "demo", 0, i,
                  router.sends[i], router.recvs[i]) for i in range(4)]
    values = [17, 29]
    tasks = [asyncio.create_task(node.run(values if i == 0 else None)) for i, node in enumerate(nodes)]
    try:
        outputs = await asyncio.wait_for(asyncio.gather(*(n.output_queue.get() for n in nodes)), 60)
        recovered = [int(nodes[0].b.poly.interpolate([(i+1, ZR(outputs[i][k])) for i in range(2)])(ZR(0))) for k in range(2)]
        assert recovered == values, (recovered, values)
        print("PASS: four parties shared and reconstructed", recovered)
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for node in nodes: await node.close()

if __name__ == "__main__":
    asyncio.run(main())
