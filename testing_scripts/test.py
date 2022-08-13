import tuya
import asyncio
import logging

device_id = b'bf226cdd832e34d581csjs'
device_key = b'3f459282e979b65c'

logging.basicConfig(level=logging.DEBUG)

async def main():
    loop = asyncio.get_running_loop()
    on_connected_future = loop.create_future()

    device = tuya.TuyaAgent34(device_id, device_key, on_connected_future, tuya.EmptyListener())
    
    task_connect = asyncio.create_task(device.connect("10.0.0.4"))

    await asyncio.wait({task_connect})

    await asyncio.sleep(10)

    await device.update_dps()

    await asyncio.sleep(20)

    # await asyncio.wait_for(on_connected_future, timeout=10)

asyncio.run(main(), debug=True)