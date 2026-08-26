# MiBLE LYWSD03MMC Passive Capture & Analysis Toolkit

一个用于 **Xiaomi Mijia LYWSD03MMC 温湿度计 BLE 广播抓取、解密和数据分析** 的 Python 工具集。

本项目目标是在 **Windows 11 + ESP32 后续移植开发之前**，先完成对 LYWSD03MMC 被动广播协议的研究，包括：

* BLE 广播数据实时抓取
* FE95 Xiaomi BLE 数据解析
* AES-CCM 解密
* 温度 / 湿度 / 电池数据提取
* 广播周期分析
* 长报文发送规律分析

本项目不主动连接温度计，而是采用 **Passive BLE Advertisement Monitoring（被动广播监听）** 方式获取数据。

---

# 功能概览

当前项目包含 4 个 Python 工具：

| 文件                | 功能                 |
| ----------------- | ------------------ |
| `MiBLECapture.py` | Windows BLE 广播抓包工具 |
| `CsvDecrypt.py`   | CSV 数据解密工具         |
| `DataAnalyst.py`  | 原始抓包数据解析与间隔分析工具    |
| `间隔分析.py`         | 长报文发送周期行为分析工具      |

---

# 数据流程

整体流程：

```
LYWSD03MMC
        |
        |
        v
MiBLECapture.py
        |
        |
        v
原始抓包 CSV
        |
        |
        +----------------+
        |                |
        v                v
CsvDecrypt.py       DataAnalyst.py
        |                |
        |                |
        v                v
解密数据CSV      decoded.csv
                         |
                         |
                         v
                 interval.csv

                         |
                         v

                 间隔分析.py

                         |
                         v

                 行为分析CSV
```

---

# 1. MiBLECapture.py

## 功能

Windows 11 下使用 BLE Advertisement Watcher 实时监听 LYWSD03MMC 广播。

主要功能：

* 手动输入目标 MAC 地址
* 自动处理 Xiaomi BLE MAC 地址方向问题
* 过滤目标设备
* 保存所有 FE95 长广播数据
* 实时写入 CSV
* 支持长时间运行
* 保存毫秒级时间戳

---

## 输出格式

例如：

```
capture.csv
```

字段：

| 字段            | 说明              |
| ------------- | --------------- |
| timestamp     | Unix 时间戳        |
| time          | 真实时间            |
| mac           | BLE设备地址         |
| rssi          | 信号强度            |
| scan_response | 是否scan response |
| sections      | BLE广播内容         |

---

# 2. CsvDecrypt.py

## 功能

对抓取后的 CSV 文件进行：

* FE95 协议解析
* AES-CCM 解密
* 温度解析
* 湿度解析
* 电池解析
* 重复广播过滤

输出：

```
decoded.csv
```

包含：

* 原始数据
* frame信息
* counter
* nonce
* MIC
* plaintext
* 数据类型
* 数值

示例：

| data_type   | value |
| ----------- | ----- |
| temperature | 28.5  |
| humidity    | 61.6  |
| battery     | 100   |

---

# 3. DataAnalyst.py

## 功能

输入：

```
capture_xxx.csv
```

自动生成：

```
capture_xxx_decoded.csv
```

以及：

```
capture_xxx_interval.csv
```

---

## decoded 文件

每一条长报文都会解码：

字段：

| 字段        | 说明                           |
| --------- | ---------------------------- |
| raw       | 原始FE95数据                     |
| type      | 数据类型ID                       |
| pid       | frame PID                    |
| mac       | 广播MAC                        |
| cipher    | 密文                           |
| counter   | 计数器                          |
| mic       | 认证字段                         |
| nonce     | AES CCM nonce                |
| status    | 解密状态                         |
| plaintext | 明文                           |
| data_type | temperature/humidity/battery |
| value     | 数值                           |
| time      | 时间                           |
| timestamp | Unix时间戳                      |
| rssi      | 信号强度                         |

---

## interval 文件

分析长报文之间的时间间隔：

例如：

```
from,to,interval_sec

humidity,humidity,0.266
humidity,temperature,57.941
temperature,battery,537.2
```

用途：

* 分析温度计广播周期
* 分析温湿度电池发送顺序
* 推断广播占空比

---

# 4. 间隔分析.py

## 功能

分析温度计长报文广播行为。

输入：

```
capture_xxx.csv
```

输出：

```
capture_xxx间隔分析.csv
```

---

输出内容：

| 字段                  | 说明       |
| ------------------- | -------- |
| group               | 广播组编号    |
| type                | 温度/湿度/电池 |
| first_time          | 该组第一条时间  |
| last_time           | 该组最后一条时间 |
| duration_seconds    | 持续时间     |
| packet_count        | 收到包数量    |
| value_first         | 第一次数值    |
| value_last          | 最后数值     |
| next_group_interval | 下一组间隔    |

用途：

分析：

* 每轮广播持续时间
* 三种数据发送顺序
* 休眠时间
* 广播周期

---

# 协议解析来源

本项目 FE95 Xiaomi BLE 解密算法参考：

Arduino ESP32 LYWSD03MMC Passive BLE 项目：

https://github.com/Saterwang/Arduino_ESP32_LYWSD03MMC_BLE_Passive

感谢该项目提供：

* FE95协议解析思路
* AES-CCM解密流程
* Nonce构造方式
* LYWSD03MMC广播格式分析

---

# 获取 MAC 地址和 BLE KEY

LYWSD03MMC 广播数据采用加密方式。

使用前需要获取：

* 温度计 MAC 地址
* BLE KEY

推荐工具：

Xiaomi-cloud-tokens-extractor

https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor

通过自己的小米账号登录后，可以获取绑定设备信息。

需要保存：

```
MAC:

A4:C1:38:31:D4:17


BLE KEY:

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

# 环境要求

## 操作系统

目前主要支持：

```
Windows 11
```

原因：

抓包部分依赖 Windows Bluetooth Runtime API。

---

# Python版本

推荐：

```
Python >= 3.10
```

---

# Python依赖

安装：

```
pip install -r requirements.txt
```

requirements.txt：

```
winrt-runtime
winrt-Windows.Devices.Bluetooth
winrt-Windows.Devices.Bluetooth.Advertisement

cryptography
pandas
```

---

# 依赖说明

## winrt

用于访问 Windows BLE API：

```
BluetoothLEAdvertisementWatcher
BluetoothLEAdvertisement
```

负责：

* BLE扫描
* Advertisement监听
* RSSI读取

---

## cryptography

用于 AES-CCM 解密：

算法：

```
AES-128 CCM
```

用于解析 Xiaomi FE95 加密广播。

---

## pandas

用于：

* CSV读取
* 数据处理
* 分析结果输出

---

# 使用流程

## 第一步：获取设备信息

运行：

Xiaomi-cloud-tokens-extractor

获取：

```
MAC
BLE KEY
```

---

## 第二步：抓取广播

运行：

```
python MiBLECapture.py
```

输入：

```
采集时间:
3600

MAC:
A4:C1:38:31:D4:17
```

生成：

```
capture.csv
```

---

## 第三步：解密分析

运行：

```
python DataAnalyst.py
```

输入：

```
capture.csv
```

生成：

```
capture_decoded.csv

capture_interval.csv
```

---

## 第四步：分析广播规律

运行：

```
python 间隔分析.py
```

输入：

```
capture.csv
```

得到：

```
capture间隔分析.csv
```

---

# 研究结论（当前）

通过大量抓包分析，目前发现 LYWSD03MMC 广播规律：

* 平时持续发送短广播
* 每隔约10分钟左右进入数据广播周期
* 数据广播持续约3秒
* 单个数据类型连续发送多个包
* 温度、湿度、电池按照一定顺序发送
* 每条数据约发送8~15次
* 单组广播持续约2~3秒

该规律将用于后续 ESP32 被动监听算法设计。

---

# 后续计划

## ESP32移植

计划实现：

* ESP32 BLE Passive Scan
* 非阻塞扫描任务
* 与WiFi/MQTT共存
* 低功耗周期监听

目标：

在不影响 WiFi 通信的情况下：

* 每小时获取一次温度
* 每小时获取一次湿度
* 定期获取电池状态

---

# License

MIT License

欢迎学习、修改和二次开发。
