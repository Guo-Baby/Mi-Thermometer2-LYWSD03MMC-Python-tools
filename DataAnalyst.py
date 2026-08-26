import csv
import ast
import os
from datetime import datetime
from tkinter import Tk, filedialog

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

KEY = None

DEVICE_MAC = None
DEVICE_MAC_REVERSED = None

AAD = b"\x11"

# =========================
# 选择文件
# =========================
def select_csv():
    Tk().withdraw()
    filename = filedialog.askopenfilename(
        filetypes=[
            ("CSV files","*.csv")
        ]
    )
    return filename

# =========================
# HEX清理
# =========================
def clean_hex(s):
    if isinstance(s, bytes):
        return s
    return bytes.fromhex(
        s.replace(" ","")
    )

def reverse_mac(mac):

    return ":".join(
        reversed(
            mac.split(":")
        )
    )

# =========================
# FE95解密
# =========================
def parse_fe95(hex_string):
    data = clean_hex(hex_string)
    if len(data) < 24:
        return None
    if data[0:2] != b"\x95\xFE":
        return None
    result={}
    result["raw"] = data.hex(" ").upper()
    type_id=data[4:6]
    pid=data[6:7]
    mac=data[7:13]
    counter=data[-7:-4]
    mic=data[-4:]
    cipher=data[13:-7]
    result["type"]=type_id.hex(" ").upper()
    result["pid"]=pid.hex(" ").upper()
    result["mac"]=mac.hex(" ").upper()
    packet_mac = ":".join(
        f"{x:02X}"
        for x in mac
    )


    if packet_mac != DEVICE_MAC_REVERSED:

        return None    
    result["cipher"]=cipher.hex(" ").upper()
    result["counter"]=counter.hex(" ").upper()
    result["mic"]=mic.hex(" ").upper()
    nonce = (
        mac
        +
        type_id
        +
        pid
        +
        counter
    )
    result["nonce"]=nonce.hex(" ").upper()
    try:
        aes=AESCCM(
            KEY,
            tag_length=4
        )
        plain=aes.decrypt(
            nonce,
            cipher+mic,
            AAD
        )
        result["status"]="SUCCESS"
        result["plaintext"]=plain.hex(" ").upper()
        if (
            len(plain)>=5
            and plain[0]==0x04
            and plain[1]==0x10
        ):
            raw=plain[3] | (plain[4]<<8)
            result["data_type"]="temperature"
            result["value"]=raw/10
        elif (
            len(plain)>=5
            and plain[0]==0x06
            and plain[1]==0x10
        ):
            raw=plain[3] | (plain[4]<<8)
            result["data_type"]="humidity"
            result["value"]=raw/10
        elif (
            len(plain)>=4
            and plain[0]==0x0A
            and plain[1]==0x10
        ):
            result["data_type"]="battery"
            result["value"]=plain[3]
        else:
            result["data_type"]="unknown"
            result["value"]=""
    except Exception:
        result["status"]="FAILED"
        return None
    return result



# =========================
# sections提取FE95
# =========================
def extract_fe95(sections):
    try:
        items=ast.literal_eval(sections)
        for item in items:
            if item["type"]=="0x16":
                hexdata=item["hex"]
                if hexdata.startswith(
                    "95 FE"
                ):
                    return hexdata
    except:
        pass
    return None

# =========================
# 时间转换
# =========================
def parse_time(t):
    dt=datetime.strptime(
        t,
        "%Y-%m-%d %H:%M:%S.%f"
    )
    return dt.timestamp()

# =========================
# 主程序
# =========================
def main():

    global KEY
    global DEVICE_MAC
    global DEVICE_MAC_REVERSED


    print("==============================")
    print("请输入 BLE KEY")
    print("格式要求:")
    print("32位十六进制字符")
    print("例如:")
    print("1234567890abcdef1234567890abcdef")
    print("格式错误或输入错误的key会导致解码失败")
    print("==============================")


    ble_key=input(
        "BLE KEY: "
    )


    if len(ble_key)!=32:

        print(
            "错误: BLE KEY长度必须32位"
        )

        return


    try:

        KEY=bytes.fromhex(
            ble_key
        )

    except:

        print(
            "ble key格式错误"
        )

        return



    DEVICE_MAC=input(
        "请输入设备MAC(例如 A1:B1:C1:D1:E1:D1，必须严格按照大写，半角冒号分隔的格式输入，错误的格式和MAC地址会导致抓包失败): "
    ).upper()


    DEVICE_MAC_REVERSED=reverse_mac(
        DEVICE_MAC
    )


    filename=select_csv()
    if not filename:
        return
    print("Loading:")
    print(filename)
    decoded=[]
    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as f:
        reader=csv.DictReader(f)
        for row in reader:
            fe95=extract_fe95(
                row["sections"]
            )
            if not fe95:
                continue
            result=parse_fe95(
                fe95
            )
            if not result:
                continue
            result["time"]=row["time"]
            result["timestamp"]=parse_time(
                row["time"]
            )
            result["rssi"]=row["rssi"]
            decoded.append(result)
    if not decoded:
        print("No decoded packets")
        return
    decoded.sort(
        key=lambda x:x["timestamp"]
    )
    # =====================
    # 输出全部解码
    # =====================
    base=os.path.splitext(filename)[0]
    output1=base+"_decoded.csv"
    with open(
        output1,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer=csv.DictWriter(
            f,
            fieldnames=decoded[0].keys()
        )
        writer.writeheader()
        writer.writerows(decoded)
    print(
        "Decoded saved:",
        output1
    )
    # =====================
    # 分析发送规律
    # =====================
    summary=[]
    last_type=None
    last_time=None
    for item in decoded:
        if last_type:
            summary.append(
                {
                "from":
                    last_type,
                "to":
                    item["data_type"],
                "interval_sec":
                    round(
                        item["timestamp"]
                        -
                        last_time,
                        3
                    )
                }
            )
        last_type=item["data_type"]
        last_time=item["timestamp"]
    output2=base+"_interval.csv"
    with open(
        output2,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:
        writer=csv.DictWriter(
            f,
            fieldnames=[
                "from",
                "to",
                "interval_sec"
            ]
        )
        writer.writeheader()
        writer.writerows(summary)
    print(
        "Interval saved:",
        output2
    )
    print()
    print("===== Sequence =====")
    for x in decoded:
        print(
            datetime.fromtimestamp(
                x["timestamp"]
            ),
            x["data_type"],
            x["value"]
        )

if __name__=="__main__":
    main()