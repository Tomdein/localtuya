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

    device.list_available_datapoints("aubess_smart_switch_1_gang")

    await asyncio.sleep(5)

    await device.set_dp(True, 1)

    await asyncio.sleep(5)

    await device.set_dp(False, 1)

    await asyncio.sleep(5)

    await device.set_dp(3, 9)

asyncio.run(main(), debug=True)
