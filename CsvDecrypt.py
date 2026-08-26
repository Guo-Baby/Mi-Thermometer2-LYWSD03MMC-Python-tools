import csv
import ast
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


# =========================
# 配置
# =========================

KEY = None

OUTPUT_FILE = None

AAD = b"\x11"


# =========================
# 文件选择
# =========================

def select_csv():

    root = tk.Tk()
    root.withdraw()

    filename = filedialog.askopenfilename(
        title="Select capture CSV",
        filetypes=[
            ("CSV files","*.csv"),
            ("All files","*.*")
        ]
    )

    return filename



# =========================
# HEX工具
# =========================

def clean_hex(s):

    return bytes.fromhex(
        s.replace(" ","")
    )



# =========================
# 数据解析
# =========================

def parse_fe95(hex_string):

    data = clean_hex(hex_string)


    # 长度检查

    if len(data) < 24:
        return None


    # FE95

    if data[0:2] != b"\x95\xFE":
        return None



    result={}


    result["raw"] = data.hex(" ").upper()


    # --------------------
    # 协议拆包
    # --------------------

    result["service"] = data[0:2].hex(" ").upper()

    result["frame_ctrl"] = data[2:4].hex(" ").upper()
    # --------------------
    # 动态解析
    # --------------------

    mac = data[7:13]

    type_id = data[4:6]

    pid = data[6:7]


    # 最后7字节固定：
    # counter 3
    # MIC 4

    counter = data[-7:-4]

    mic = data[-4:]


    # 中间全部属于cipher

    cipher = data[13:-7]



    result["type"] = type_id.hex(" ").upper()

    result["pid"] = pid.hex(" ").upper()

    result["mac"] = mac.hex(" ").upper()

    result["cipher"] = cipher.hex(" ").upper()

    result["counter"] = counter.hex(" ").upper()

    result["mic"] = mic.hex(" ").upper()



    # --------------------
    # nonce
    # --------------------

    nonce = (
        mac
        +
        type_id
        +
        pid
        +
        counter
    )


    result["nonce"] = nonce.hex(" ").upper()



    # --------------------
    # AES CCM
    # --------------------

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


        result["status"]="SUCCESS"

        result["plaintext"] = (
            plain.hex(" ").upper()
        )


        # ----------------
        # 数据解析
        # ----------------

        value_type = ""
        value = ""


        # ----------------
        # 明文解析
        # ----------------

        value_type = ""
        value = ""


        # 温度
        if (
            len(plain) >= 5
            and plain[0] == 0x04
            and plain[1] == 0x10
        ):

            raw = (
                plain[3]
                |
                (plain[4] << 8)
            )

            value_type = "temperature"

            value = raw / 10



        # 湿度
        elif (
            len(plain) >= 5
            and plain[0] == 0x06
            and plain[1] == 0x10
        ):

            raw = (
                plain[3]
                |
                (plain[4] << 8)
            )

            value_type = "humidity"

            value = raw / 10



        # 电池
        if len(plain)>=4:


            if plain[0]==0x0A and plain[1]==0x10:

                value_type="battery"

                value = plain[3]



        result["data_type"]=value_type

        result["value"]=value



    except Exception as e:


        result["status"]="FAILED"

        result["plaintext"]=""

        result["data_type"]=""

        result["value"]=""

        result["error"]=str(e)



    return result




# =========================
# 主程序
# =========================


def main():

    global KEY
    global OUTPUT_FILE

    print("==============================")
    print("请输入 BLE KEY")
    print("格式要求:")
    print("32位十六进制字符")
    print("例如:")
    print("a1234567890abcde1234567890abcdef")
    print("格式错误或输入错误的key或导致解码失败")
    print("==============================")


    ble_key = input(
        "BLE KEY: "
    )


    KEY = bytes.fromhex(
    ble_key
    )


    if len(KEY) != 16:

        print(
            "错误: BLE KEY 必须是16字节(32个十六进制字符)"
        )

        return


    input_file = select_csv()


    if not input_file:

        print("No file selected")

        return
    

    # 根据输入文件自动生成输出文件名

    if input_file.lower().endswith(".csv"):

        OUTPUT_FILE = (
            input_file[:-4]
            +
            "_decrypted.csv"
        )

    else:

        OUTPUT_FILE = (
            input_file
            +
            "_decrypted.csv"
        )


    print()

    print("==============================")

    print("Input:")

    print(input_file)

    print("==============================")



    results=[]

    duplicate=set()


    total=0

    success=0



    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as f:


        reader = csv.DictReader(f)



        for row in reader:


            total += 1


            try:

                sections = ast.literal_eval(
                    row["sections"]
                )


            except Exception:

                continue



            for section in sections:


                if section["type"] != "0x16":

                    continue



                hex_data = section["hex"]



                if not hex_data.startswith(
                    "95 FE"
                ):

                    continue



                parsed = parse_fe95(
                    hex_data
                )


                if not parsed:

                    continue



                key = (

                    parsed["mac"],

                    parsed["counter"],

                    parsed["cipher"]

                )


                if key in duplicate:

                    continue



                duplicate.add(key)



                parsed["time"] = row["time"]

                parsed["rssi"] = row["rssi"]



                results.append(parsed)



                if parsed["status"]=="SUCCESS":

                    success+=1




    print()

    print(
        "Packets:",
        total
    )

    print(
        "Unique:",
        len(results)
    )

    print(
        "Decrypt success:",
        success
    )




    # ======================
    # 保存
    # ======================


    if results:


        fields=list(results[0].keys())


        with open(
            OUTPUT_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:


            writer=csv.DictWriter(
                f,
                fieldnames=fields
            )


            writer.writeheader()

            writer.writerows(results)



        print()

        print(
            "Saved:",
            OUTPUT_FILE
        )



    else:

        print(
            "No decoded packet"
        )



if __name__=="__main__":

    main()