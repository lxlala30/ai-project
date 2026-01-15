#!/usr/bin/python
# -*- coding: UTF-8 -*-

import json
import time
import requests
import paho.mqtt.client as mqtt
import threading
import pyaudio
import os
import sys
from colorama import init, Fore, Back, Style

# 初始化colorama
init()

# 检查opus.dll
def check_opus_dll():
    system32_path = os.path.join(os.environ['SystemRoot'], 'System32', 'opus.dll')
    if not os.path.exists(system32_path):
        print(f"{COLORS['ERROR']}错误：未找到opus.dll文件！{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}请将opus.dll文件复制到 C:\\Windows\\System32 目录下{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}下载地址：https://github.com/QiKeO/py-xiaozhi{COLORS['RESET']}")
        return False
    return True

# 在其他import之前先检查opus.dll
if sys.platform == 'win32' and not check_opus_dll():
    sys.exit(1)

import opuslib
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom, path
import signal
import logging
from pynput import keyboard as pynput_keyboard
import uuid

# 颜色常量定义
COLORS = {
    'USER_INPUT': Fore.GREEN,
    'SYSTEM_STATUS': Fore.LIGHTBLACK_EX,
    'AI_RESPONSE': Fore.BLUE,
    'ERROR': Fore.RED,
    'RESET': Style.RESET_ALL
}

# 状态图标
ICONS = {
    'RECORDING': '🎤',
    'THINKING': '💭',
    'PLAYING': '▶️',
    'PAUSED': '⏸️',
    'RECOGNIZED': '✓',
    'AI': '🤖'
}

def get_or_create_device_id():
    """获取或创建设备唯一标识"""
    config_file = 'device_config.json'
    if path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            return config['device_id'], config['mac_addr']
    
    # 生成新的设备ID和MAC地址
    device_id = str(uuid.uuid4())
    mac_parts = [format(uuid.uuid4().int >> i & 0xFF, '02x') for i in (40, 32, 24, 16, 8, 0)]
    mac_addr = ':'.join(mac_parts)
    
    # 保存配置
    config = {'device_id': device_id, 'mac_addr': mac_addr}
    with open(config_file, 'w') as f:
        json.dump(config, f)
    
    return device_id, mac_addr

# 获取设备唯一标识
DEVICE_ID, MAC_ADDR = get_or_create_device_id()

OTA_VERSION_URL = 'https://api.tenclass.net/xiaozhi/ota/'
mqtt_info = {}
aes_opus_info = {
    "type": "hello",
    "version": 3,
    "transport": "udp",
    "udp": {
        "server": "120.24.160.13",
        "port": 8884,
        "encryption": "aes-128-ctr",
        "key": urandom(16).hex(),  # 生成随机密钥
        "nonce": urandom(16).hex()  # 生成随机nonce
    },
    "audio_params": {
        "format": "opus",
        "sample_rate": 24000,
        "channels": 1,
        "frame_duration": 60
    },
    "session_id": str(uuid.uuid4())  # 生成唯一会话ID
}

local_sequence = 0
listen_state = None
tts_state = None
key_state = None
audio = None
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
conn_state = False
recv_audio_thread = threading.Thread()
send_audio_thread = threading.Thread()
mqttc = None

# 在全局变量部分新增: 自动模式标志 音频流对象
auto_mode = False
mic_stream = None
# 在全局变量中添加，心跳检测线程 心跳标记
heartbeat_thread = None
heartbeat_active = False

restart_flag = False  # 标记是否需要重启
exit_flag = False     # 标记是否完全退出

# ota升级版本
def get_ota_version():
    global mqtt_info
    header = {
        'Device-Id': MAC_ADDR,
        'Content-Type': 'application/json'
    }
    post_data = {"flash_size": 16777216, "minimum_free_heap_size": 8318916, "mac_address": f"{MAC_ADDR}",
                 "chip_model_name": "esp32s3", "chip_info": {"model": 9, "cores": 2, "revision": 2, "features": 18},
                 "application": {"name": "xiaozhi", "version": "0.9.9", "compile_time": "Jan 22 2025T20:40:23Z",
                                 "idf_version": "v5.3.2-dirty",
                                 "elf_sha256": "22986216df095587c42f8aeb06b239781c68ad8df80321e260556da7fcf5f522"},
                 "partition_table": [{"label": "nvs", "type": 1, "subtype": 2, "address": 36864, "size": 16384},
                                     {"label": "otadata", "type": 1, "subtype": 0, "address": 53248, "size": 8192},
                                     {"label": "phy_init", "type": 1, "subtype": 1, "address": 61440, "size": 4096},
                                     {"label": "model", "type": 1, "subtype": 130, "address": 65536, "size": 983040},
                                     {"label": "storage", "type": 1, "subtype": 130, "address": 1048576,
                                      "size": 1048576},
                                     {"label": "factory", "type": 0, "subtype": 0, "address": 2097152, "size": 4194304},
                                     {"label": "ota_0", "type": 0, "subtype": 16, "address": 6291456, "size": 4194304},
                                     {"label": "ota_1", "type": 0, "subtype": 17, "address": 10485760,
                                      "size": 4194304}],
                 "ota": {"label": "factory"},
                 "board": {"type": "bread-compact-wifi", "ssid": "mzy", "rssi": -58, "channel": 6,
                           "ip": "192.168.124.38", "mac": "cc:ba:97:20:b4:bc"}}

    response = requests.post(OTA_VERSION_URL, headers=header, data=json.dumps(post_data))
    print('=========================')
    print(response.text)
    logging.info(f"get version: {response}")
    mqtt_info = response.json()['mqtt']

# 加密
def aes_ctr_encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# 解密
def aes_ctr_decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


# 修改 send_audio() 函数
def send_audio():
    global aes_opus_info, udp_socket, local_sequence, auto_mode, mic_stream
    key = aes_opus_info['udp']['key']
    nonce = aes_opus_info['udp']['nonce']
    server_ip = aes_opus_info['udp']['server']
    server_port = aes_opus_info['udp']['port']
    encoder = opuslib.Encoder(16000, 1, opuslib.APPLICATION_AUDIO)
    
    # 强制初始化麦克风流（解决流丢失问题）
    if mic_stream is None:
        try:
            mic_stream = audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=16000,
                input=True,
                frames_per_buffer=960
            )
            print(f"{COLORS['SYSTEM_STATUS']}麦克风流已初始化{COLORS['RESET']}")
        except Exception as e:
            print(f"{COLORS['ERROR']}麦克风初始化失败: {str(e)}{COLORS['RESET']}")
            return

    try:
        while True:
            # 仅手动模式检查 listen_state
            if not auto_mode and listen_state != "start":
                time.sleep(0.1)
                continue

            try:
                # 持续读取音频（关键修改：移除条件判断）
                data = mic_stream.read(960, exception_on_overflow=False)
                encoded_data = encoder.encode(data, 960)
                #if auto_mode:
                #时间转换
                #curTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.mktime(time.localtime())))
                #print(f"DEBUG: [{curTime}]: 发送音频帧 seq={local_sequence} size={len(encoded_data)} auto={auto_mode}")
                
                # 加密数据包
                local_sequence += 1
                new_nonce = nonce[0:4] + format(len(encoded_data), '04x') + nonce[8:24] + format(local_sequence, '08x')
                encrypted_data = aes_ctr_encrypt(
                    bytes.fromhex(key),
                    bytes.fromhex(new_nonce),
                    bytes(encoded_data)
                )
                packet = bytes.fromhex(new_nonce) + encrypted_data
                udp_socket.sendto(packet, (server_ip, server_port))
                
            except IOError as e:
                print(f"{COLORS['ERROR']}音频读取错误: {str(e)}{COLORS['RESET']}")
                if auto_mode:
                    # 自动模式：强制重启流
                    restart_mic_stream()
                    time.sleep(0.5)  # 防抖
                    continue
                break
                
            except Exception as e:
                print(f"{COLORS['ERROR']}未知错误: {str(e)}{COLORS['RESET']}")
                if auto_mode:
                    time.sleep(1)
                    continue
                break

    finally:
        # 仅在完全退出时关闭流
        if not auto_mode:
            close_mic_stream()

def restart_mic_stream():
    """强制重启麦克风流"""
    global mic_stream
    close_mic_stream()
    time.sleep(0.2)
    try:
        mic_stream = audio.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=16000,
            input=True,
            frames_per_buffer=960
        )
        print(f"{COLORS['SYSTEM_STATUS']}麦克风流已重启{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['ERROR']}麦克风重启失败: {str(e)}{COLORS['RESET']}")

def close_mic_stream():
    """安全关闭麦克风流"""
    global mic_stream
    if mic_stream:
        try:
            mic_stream.stop_stream()
            mic_stream.close()
        except Exception as e:
            print(f"{COLORS['ERROR']}关闭麦克风流异常: {str(e)}{COLORS['RESET']}")
        finally:
            mic_stream = None

#收到音频时解析逻辑
def recv_audio():
    global aes_opus_info, udp_socket, audio
    key = aes_opus_info['udp']['key']
    nonce = aes_opus_info['udp']['nonce']
    sample_rate = aes_opus_info['audio_params']['sample_rate']
    frame_duration = aes_opus_info['audio_params']['frame_duration']
    frame_num = int(frame_duration / (1000 / sample_rate))
    # 初始化Opus编码器
    decoder = opuslib.Decoder(sample_rate, 1)
    spk = audio.open(format=pyaudio.paInt16, channels=1, rate=sample_rate, output=True, frames_per_buffer=frame_num)
    try:
        while True:
            data, server = udp_socket.recvfrom(4096)
            encrypt_encoded_data = data
            # 解密数据,分离nonce
            split_encrypt_encoded_data_nonce = encrypt_encoded_data[:16]
            split_encrypt_encoded_data = encrypt_encoded_data[16:]
            decrypt_data = aes_ctr_decrypt(bytes.fromhex(key),
                                           split_encrypt_encoded_data_nonce,
                                           split_encrypt_encoded_data)
            # 解码播放音频数据
            spk.write(decoder.decode(decrypt_data, frame_num))
    except Exception as e:
        print(f"{COLORS['ERROR']}接收音频错误：{str(e)}{COLORS['RESET']}")
    finally:
        udp_socket = None
        spk.stop_stream()
        spk.close()

# mqtt连接初始化
def on_connect(client, userdata, flags, rs):
    if rs != 0:  # 只在连接失败时显示错误
        print(f"{COLORS['ERROR']}❌ MQTT服务器连接失败，错误码：{rs}{COLORS['RESET']}")
        return
    
    # 订阅特定设备的主题
    subscribe_topic = f"{mqtt_info['subscribe_topic'].split('/')[0]}/p2p/GID_test@@@{MAC_ADDR.replace(':', '_')}"
    client.subscribe(subscribe_topic)

# 重启当前脚本
def restart_program():
    """重启当前脚本"""
    global restart_flag, exit_flag
    if exit_flag:  # 如果已经标记为退出，则不重启
        return
    restart_flag = True
    print(f"{COLORS['SYSTEM_STATUS']}🔄 正在重启应用...{COLORS['RESET']}")
    time.sleep(0.5)  # 防抖
    
    # 关闭所有资源
    try:
        if mqttc:
            mqttc.loop_stop()
            mqttc.disconnect()
        if audio:
            audio.terminate()
        if udp_socket:
            udp_socket.close()
        if recv_audio_thread.is_alive():
            recv_audio_thread.join(timeout=1)
        if send_audio_thread.is_alive():
            send_audio_thread.join(timeout=1)
    except Exception as e:
        print(f"{COLORS['ERROR']}重启错误：{str(e)}{COLORS['RESET']}")
    
    # 重启进程
    python = sys.executable
    os.execl(python, python, *sys.argv)
    print(f"{COLORS['SYSTEM_STATUS']}🔄 等待重启应用...{COLORS['RESET']}")

# 新增：切换自动/手动模式
def toggle_auto_mode():
    global auto_mode, listen_state
    auto_mode = not auto_mode
    mode_name = "自动" if auto_mode else "手动"
    print(f"{COLORS['SYSTEM_STATUS']}🔄 已切换为 {mode_name} 对话模式{COLORS['RESET']}")
    
    if auto_mode:
        # 强制进入持续录音状态
        listen_state = "start"
        print(f"{COLORS['SYSTEM_STATUS']}{ICONS['RECORDING']} 自动模式：持续聆听中...{COLORS['RESET']}")
        
        # 确保麦克风就绪
        restart_mic_stream()
        
        # 分两次发送启动消息（解决服务器状态同步问题）
        if aes_opus_info.get('session_id'):
            for _ in range(2):  # 双重发送确保服务器接收
                push_mqtt_msg({
                    "session_id": aes_opus_info['session_id'],
                    "type": "listen",
                    "state": "start",
                    "mode": "auto"
                })
                time.sleep(0.1)  # 短暂间隔
    else:
        # 手动模式：停止录音
        listen_state = "stop"
        if aes_opus_info.get('session_id'):
            push_mqtt_msg({
                "session_id": aes_opus_info['session_id'],
                "type": "listen",
                "state": "stop"
            })

def start_heartbeat():
    """启动心跳线程"""
    global heartbeat_active, heartbeat_thread
    
    def heartbeat_loop():
        while heartbeat_active:
            if auto_mode and aes_opus_info.get('session_id'):
                push_mqtt_msg({
                    "session_id": aes_opus_info['session_id'],
                    "type": "heartbeat",
                    "mode": "auto"
                })
            time.sleep(5)  # 每5秒一次
    
    heartbeat_active = True
    heartbeat_thread = threading.Thread(target=heartbeat_loop)
    heartbeat_thread.daemon = True
    heartbeat_thread.start()

def stop_heartbeat():
    """停止心跳线程"""
    global heartbeat_active
    heartbeat_active = False
    if heartbeat_thread:
        heartbeat_thread.join(timeout=1)

# 修改 toggle_auto_mode() 在启用自动模式时调用 start_heartbeat()
# 禁用自动模式时调用 stop_heartbeat()

# 修改键盘监听逻辑
def on_press(key):
    # print(key)
    global restart_flag, exit_flag, auto_mode
    try:
        if key == pynput_keyboard.Key.space:
            if not auto_mode:  # 手动模式下才响应空格键
                on_space_key_press(None)
        elif key == pynput_keyboard.Key.esc:
            exit_flag = True
            print(f"\n{COLORS['SYSTEM_STATUS']}👋 感谢使用小智语音助手，再见！{COLORS['RESET']}")
            os.kill(os.getpid(), signal.SIGINT)
            return False
        elif key == pynput_keyboard.Key.ctrl:
            print(f"\n{COLORS['SYSTEM_STATUS']}👋 欢迎再次使用小智语音助手！{COLORS['RESET']}")
        elif hasattr(key, 'char') and key.char == 'r' and not exit_flag:
            print(f"\n{COLORS['SYSTEM_STATUS']}按R键重新启动！{COLORS['RESET']}")
            restart_program()
        elif hasattr(key, 'char') and key.char == 't' and not exit_flag:
            print(f"\n{COLORS['SYSTEM_STATUS']}按T键切换手/自动！{COLORS['RESET']}")
            toggle_auto_mode()
    except Exception as e:
        print(f"{COLORS['ERROR']}键盘监听错误: {str(e)}{COLORS['RESET']}")

#收到消息时回调处理
def on_message(client, userdata, message):
    global aes_opus_info, udp_socket, tts_state, recv_audio_thread, send_audio_thread
    msg = json.loads(message.payload)
    
    # 根据消息类型处理不同的显示效果
    if msg['type'] == 'stt':
        print(f"{COLORS['USER_INPUT']}{ICONS['RECOGNIZED']} 已识别：{msg['text']}{COLORS['RESET']}")
    
    elif msg['type'] == 'tts':
        tts_state = msg['state']  # 更新tts状态
        if msg['state'] == 'sentence_start':
            # 如果消息中包含验证码,添加控制台链接和重启提示
            if '验证码' in msg['text']:
                print(f"{COLORS['AI_RESPONSE']}{ICONS['AI']} 小智：{msg['text']}{COLORS['RESET']}")
                print(f"\n{COLORS['SYSTEM_STATUS']}📱 请访问控制台: https://xiaozhi.me/console/devices{COLORS['RESET']}")
                print(f"{COLORS['SYSTEM_STATUS']}✨ 完成设备添加后,请重启程序{COLORS['RESET']}\n")
            else:
                print(f"{COLORS['AI_RESPONSE']}{ICONS['AI']} 小智：{msg['text']}{COLORS['RESET']}")
        elif msg['state'] == 'start':
            print(f"{COLORS['SYSTEM_STATUS']}{ICONS['PLAYING']} 开始播放{COLORS['RESET']}")
        elif msg['state'] == 'stop':
            print(f"{COLORS['SYSTEM_STATUS']}{ICONS['PAUSED']} 播放结束{COLORS['RESET']}")
            #toggle_auto_mode()
    
    elif msg['type'] == 'llm':
        if 'emotion' in msg:
            print(f"{COLORS['AI_RESPONSE']}{msg['text']} ({msg['emotion']}){COLORS['RESET']}")
    
    elif msg['type'] == 'hello':
        aes_opus_info = msg
        udp_socket.connect((msg['udp']['server'], msg['udp']['port']))
        
        if not recv_audio_thread.is_alive():
            recv_audio_thread = threading.Thread(target=recv_audio)
            recv_audio_thread.start()
        
        if not send_audio_thread.is_alive():
            send_audio_thread = threading.Thread(target=send_audio)
            send_audio_thread.start()
    
    elif msg['type'] == 'goodbye' and udp_socket and msg['session_id'] == aes_opus_info['session_id']:
        aes_opus_info['session_id'] = None

#解析音频后 转发消息服务端处理
def push_mqtt_msg(message):
    global mqtt_info, mqttc
    mqttc.publish(mqtt_info['publish_topic'], json.dumps(message))


# 修改 on_space_key_press（仅手动模式生效）
def on_space_key_press(event):
    global key_state, udp_socket, aes_opus_info, listen_state, conn_state
    if key_state == "press" or auto_mode:  # 自动模式下忽略空格键
        return
    key_state = "press"
    print(f"{COLORS['SYSTEM_STATUS']}{ICONS['RECORDING']} 正在聆听...{COLORS['RESET']}")
    
    if conn_state is False or aes_opus_info['session_id'] is None:
        conn_state = True
        hello_msg = {"type": "hello", "version": 3, "transport": "udp",
                    "audio_params": {"format": "opus", "sample_rate": 16000, "channels": 1, "frame_duration": 60}}
        push_mqtt_msg(hello_msg)
        print(f"{COLORS['SYSTEM_STATUS']}正在重新建立连接...{COLORS['RESET']}")
    
    if tts_state == "start" or tts_state == "sentence_start":
        push_mqtt_msg({"type": "abort"})
        print(f"{COLORS['SYSTEM_STATUS']}已中断当前播放{COLORS['RESET']}")
    
    if aes_opus_info['session_id'] is not None:
        msg = {"session_id": aes_opus_info['session_id'], "type": "listen", "state": "start", "mode": "manual"}
        push_mqtt_msg(msg)
        listen_state = "start"  # 手动模式启动录音

# 修改 on_space_key_release（仅手动模式生效）
def on_space_key_release(event):
    global aes_opus_info, key_state, listen_state
    if key_state == "release" or auto_mode:  # 自动模式下忽略空格键
        return
    key_state = "release"
    print(f"{COLORS['SYSTEM_STATUS']}{ICONS['THINKING']} 正在处理...{COLORS['RESET']}")
    
    if aes_opus_info['session_id'] is not None:
        msg = {"session_id": aes_opus_info['session_id'], "type": "listen", "state": "stop"}
        push_mqtt_msg(msg)
        listen_state = "stop"  # 手动模式停止录音

def on_release(key):
    if key == pynput_keyboard.Key.space:
        on_space_key_release(None)

# 主程序初始化
def run():
    global mqtt_info, mqttc, audio
    
    # 显示欢迎信息
    print(f"\n{COLORS['AI_RESPONSE']}欢迎使用小智语音助手！{COLORS['RESET']}")
    print(f"{COLORS['SYSTEM_STATUS']}系统正在初始化...{COLORS['RESET']}")
    
    try:
        # 检查音频设备
        if audio.get_default_input_device_info() is None:
            print(f"{COLORS['ERROR']}错误：未检测到麦克风设备{COLORS['RESET']}")
            return
        if audio.get_default_output_device_info() is None:
            print(f"{COLORS['ERROR']}错误：未检测到扬声器设备{COLORS['RESET']}")
            return
            
        # 获取mqtt与版本信息
        print(f"{COLORS['SYSTEM_STATUS']}正在连接服务器...{COLORS['RESET']}")
        get_ota_version()
        
        # 监听键盘按键
        print(f"\n{COLORS['SYSTEM_STATUS']}✨ 系统已准备就绪！{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}📢 按住空格键开始对话，松开等待回复{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}🔄 按 T 键切换自动/手动对话模式（当前：手动）{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}❌ 按ESC键退出程序  | 🔄 按R键重启程序{COLORS['RESET']}\n")
        # print(f"{COLORS['SYSTEM_STATUS']}❌ 按ESC键退出程序{COLORS['RESET']}
        
        #键盘监听回调逻辑
        listener = pynput_keyboard.Listener(on_press=on_press, on_release=on_release)
        listener.start()
        
        # 创建MQTT客户端
        # mqttc = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_info['client_id'])
        mqttc = mqtt.Client(client_id=mqtt_info['client_id'])
        mqttc.username_pw_set(username=mqtt_info['username'], password=mqtt_info['password'])
        mqttc.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=mqtt.ssl.CERT_REQUIRED,
                      tls_version=mqtt.ssl.PROTOCOL_TLS, ciphers=None)
        mqttc.on_connect = on_connect
        mqttc.on_message = on_message
        
        try:
            mqttc.connect(host=mqtt_info['endpoint'], port=8883)
            mqttc.loop_forever()
        except Exception as e:
            print(f"{COLORS['ERROR']}MQTT连接错误：{str(e)}{COLORS['RESET']}")
            
    except KeyboardInterrupt:
        print(f"\n{COLORS['SYSTEM_STATUS']}👋 感谢使用小智语音助手，再见！{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['ERROR']}系统错误：{str(e)}{COLORS['RESET']}")
    finally:
        if audio:
            audio.terminate()

#脚本启动时主程序处理逻辑
if __name__ == "__main__":
    try:
        print(f"\n{COLORS['SYSTEM_STATUS']}✨ 系统准备启动！{COLORS['RESET']}")
        audio = pyaudio.PyAudio()
        run()
    except Exception as e:
        print(f"{COLORS['ERROR']}程序启动失败：{str(e)}{COLORS['RESET']}")
    finally:
        if not restart_flag and audio:  # 避免重启时重复释放
            audio.terminate()