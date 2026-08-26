import csv
import ast
import os
import tkinter as tk
from tkinter import filedialog
from datetime import datetime


# ==========================
# 配置
# ==========================

GROUP_GAP_SECONDS = 10





# ==========================
# 这里放你的 parse_fe95()
# ==========================

from cryptography.hazmat.primitives.ciphers.aead import AESCCM


KEY = bytes.fromhex(
    "a31686507d7afcc4d51d001eff26692a"
)

AAD = b"\x11"



def clean_hex(s):

    return bytes.fromhex(
        s.replace(" ", "")
    )



def parse_fe95(hex_string):

    data = clean_hex(hex_string)


    if len(data) < 24:
        return None


    if data[0:2] != b"\x95\xFE":
        return None


    result={}


    type_id = data[4:6]

    pid = data[6:7]

    mac = data[7:13]


    counter = data[-7:-4]

    mic = data[-4:]


    cipher = data[13:-7]


    nonce = (
        mac
        +
        type_id
        +
        pid
        +
        counter
    )


    try:

        aes = AESCCM(
            KEY,
            tag_length=4
        )


        plain = aes.decrypt(
            nonce,
            cipher + mic,
            AAD
        )


    except:

        return None



    value_type=""

    value=""


    if (
        len(plain)>=5
        and plain[0]==0x04
        and plain[1]==0x10
    ):

        raw = (
            plain[3]
            |
            (plain[4]<<8)
        )

        value_type="temperature"

        value=raw/10



    elif (
        len(plain)>=5
        and plain[0]==0x06
        and plain[1]==0x10
    ):

        raw = (
            plain[3]
            |
            (plain[4]<<8)
        )

        value_type="humidity"

        value=raw/10



    elif (
        len(plain)>=4
        and plain[0]==0x0A
        and plain[1]==0x10
    ):

        value_type="battery"

        value=plain[3]


    else:

        return None



    return {
        "type":value_type,
        "value":value
    }




# ==========================
# 时间转换
# ==========================

def parse_time(t):

    return datetime.strptime(
        t,
        "%Y-%m-%d %H:%M:%S.%f"
    )




# ==========================
# 选择文件
# ==========================

root=tk.Tk()

root.withdraw()


filename=filedialog.askopenfilename(
    title="选择capture CSV",
    filetypes=[
        ("CSV files","*.csv")
    ]
)


if not filename:

    print("没有选择文件")
    exit()



print("读取:")
print(filename)



# ==========================
# 自动生成输出文件名
# ==========================

base_name = os.path.splitext(filename)[0]


OUTPUT_FILE = (
    base_name
    +
    "间隔分析.csv"
)



print("输出:")
print(OUTPUT_FILE)


# ==========================
# 读取并解码
# ==========================


packets=[]


with open(
    filename,
    "r",
    encoding="utf-8"
) as f:


    reader=csv.DictReader(f)


    for row in reader:


        try:

            sections=ast.literal_eval(
                row["sections"]
            )


        except:

            continue



        fe95=None


        for s in sections:

            if (
                s["type"]=="0x16"
                and s["hex"].startswith(
                    "95 FE"
                )
            ):

                fe95=s["hex"]
                break



        if fe95 is None:
            continue



        decoded=parse_fe95(
            fe95
        )


        if decoded is None:
            continue



        packets.append(
            {
                "time":
                    parse_time(row["time"]),

                "type":
                    decoded["type"],

                "value":
                    decoded["value"],

                "rssi":
                    row["rssi"]
            }
        )




print()

print(
    "解码长包数量:",
    len(packets)
)




# ==========================
# 分组
# ==========================


groups=[]


current=[]



for p in packets:


    if not current:

        current.append(p)

        continue



    last=current[-1]


    gap=(
        p["time"]
        -
        last["time"]
    ).total_seconds()



    #
    # 同类型并且连续
    #

    if (
        gap <= GROUP_GAP_SECONDS
        and
        p["type"]==last["type"]
    ):

        current.append(p)



    else:

        groups.append(current)

        current=[p]



if current:

    groups.append(current)




# ==========================
# 输出分析结果
# ==========================


with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as f:


    writer=csv.writer(f)


    writer.writerow(
        [
            "group",
            "type",
            "first_time",
            "last_time",
            "duration_seconds",
            "packet_count",
            "value_first",
            "value_last",
            "next_group_interval"
        ]
    )



    for i,g in enumerate(groups):


        first=g[0]["time"]

        last=g[-1]["time"]



        duration=(
            last-first
        ).total_seconds()



        if i < len(groups)-1:

            next_gap=(
                groups[i+1][0]["time"]
                -
                last
            ).total_seconds()

        else:

            next_gap=""



        writer.writerow(
            [
                i+1,

                g[0]["type"],

                first.strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),

                last.strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),

                duration,

                len(g),

                g[0]["value"],

                g[-1]["value"],

                next_gap
            ]
        )



print()

print("======================")

print("分析完成")

print(
    "输出:",
    OUTPUT_FILE
)

print(
    "广播组数量:",
    len(groups)
)

print("======================")