import asyncio
import csv
import signal
import time
from datetime import datetime

from winrt.windows.devices.bluetooth.advertisement import (
    BluetoothLEAdvertisementWatcher,
    BluetoothLEScanningMode
)

# 程序内部BLE过滤MAC
TARGET_MAC = None
# 用户输入的真实MAC
DEVICE_MAC = None

running = True
packet_count = 0
start_time = None
# 真实时间戳起点
capture_timestamp_start = None

csv_file = None
writer = None

RUN_SECONDS = 600
OUTPUT_FILE = "MiBLEcapture.csv"

def format_mac(address):
    return ":".join(
        f"{(address >> (8*i)) & 0xFF:02X}"
        for i in range(6)
    )

# 小米BLE报文内部MAC顺序反转
def reverse_mac(mac):
    parts = mac.split(":")
    return ":".join(
        reversed(parts)
    )

def bytes_to_hex(data):
    return " ".join(
        f"{b:02X}"
        for b in data
    )

def stop_handler(sig, frame):
    global running
    print()
    print("Stopping capture...")
    running = False

def init_csv():
    global csv_file, writer
    csv_file = open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
        buffering=1
    )
    writer = csv.DictWriter(
        csv_file,
        fieldnames=[
            "timestamp",
            "time",
            "mac",
            "rssi",
            "scan_response",
            "sections"
        ]
    )
    writer.writeheader()
    csv_file.flush()

def save_record(record):
    writer.writerow(record)
    # 实时写入，防止异常丢失
    csv_file.flush()

def on_received(sender, args):
    global packet_count
    mac = format_mac(
        args.bluetooth_address
    )
    # MAC过滤
    if mac != TARGET_MAC:
        return
    adv = args.advertisement
    sections=[]
    has_fe95=False
    for section in adv.data_sections:
        data = bytes(section.data)
        sections.append(
            {
                "type":
                    hex(section.data_type),
                "hex":
                    bytes_to_hex(data)
            }
        )
        if (
            section.data_type == 0x16
            and data.startswith(b"\x95\xFE")
        ):
            has_fe95=True
    # 只保存小米MiBeacon
    if not has_fe95:
        return
    packet_count += 1
    save_record(
        {
        "timestamp":
            round(
                time.time()
                -
                capture_timestamp_start,
                3
            ),
        "time":
            datetime.now()
            .strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            ),
        "mac":
            mac,
        "rssi":
            args.raw_signal_strength_in_dbm,
        "scan_response":
            args.is_scan_response,
        "sections":
            str(sections)
        }
    )

async def main():
    global start_time
    global RUN_SECONDS
    global OUTPUT_FILE
    global capture_timestamp_start
    global TARGET_MAC
    global DEVICE_MAC

    #
    # 输入采集时间
    #
    RUN_SECONDS = int(
        input(
            "请输入采集时间(秒): "
        )
    )
    #
    # 输入真实MAC
    #
    DEVICE_MAC = input(
        "请输入设备MAC(例如 A1:B1:C1:D1:E1:D1，必须严格按照大写，半角冒号分隔的格式输入，错误的格式和MAC地址会导致抓包失败): "
    ).upper()
    #
    # 自动转换BLE过滤MAC
    #
    TARGET_MAC = reverse_mac(
        DEVICE_MAC
    )
    #
    # 输入文件名
    #
    filename = input(
        "请输入保存文件名(不用加.csv): "
    )
    OUTPUT_FILE = filename + ".csv"

    signal.signal(
        signal.SIGINT,
        stop_handler
    )

    init_csv()

    watcher = BluetoothLEAdvertisementWatcher()

    watcher.scanning_mode = (
        BluetoothLEScanningMode.ACTIVE
    )

    watcher.add_received(
        on_received
    )

    print("==============================")
    print("LYWSD03MMC Capture")
    print()
    print("Device MAC:")
    print(DEVICE_MAC)
    print()
    print("BLE Filter MAC:")
    print(TARGET_MAC)
    print()
    print("Duration:",
          RUN_SECONDS,
          "seconds")
    print()
    print("Output:",
          OUTPUT_FILE)
    print("==============================")

    start_time = asyncio.get_event_loop().time()
    capture_timestamp_start = time.time()

    watcher.start()

    try:
        last_print = -1
        while running:
            elapsed = (
                asyncio.get_event_loop().time()
                -
                start_time
            )
            remain = int(
                RUN_SECONDS
                -
                elapsed
            )
            if remain <= 0:
                print(
                    "Capture finished"
                )
                break
            # 每10秒打印一次
            current = int(elapsed)
            if current % 10 == 0 and current != last_print:
                last_print = current
                print(
                    f"[{current}s] "
                    f"remain {remain}s "
                    f"packets {packet_count}"
                )
            await asyncio.sleep(1)
    finally:
        watcher.stop()
        if csv_file:
            csv_file.flush()
            csv_file.close()
        print()
        print("================")
        print(
            "Saved:",
            OUTPUT_FILE
        )
        print(
            "Packets:",
            packet_count
        )
        print("================")

if __name__=="__main__":
    asyncio.run(main())