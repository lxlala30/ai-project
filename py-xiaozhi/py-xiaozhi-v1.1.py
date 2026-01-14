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

class XiaozhiAssistant:
    def __init__(self):
        self.device_id, self.mac_addr = self.get_or_create_device_id()
        self.ota_version_url = 'https://api.tenclass.net/xiaozhi/ota/'
        self.mqtt_info = {}
        self.aes_opus_info = {
            "type": "hello",
            "version": 3,
            "transport": "udp",
            "udp": {
                "server": "120.24.160.13",
                "port": 8884,
                "encryption": "aes-128-ctr",
                "key": urandom(16).hex(),
                "nonce": urandom(16).hex()
            },
            "audio_params": {
                "format": "opus",
                "sample_rate": 24000,
                "channels": 1,
                "frame_duration": 60
            },
            "session_id": str(uuid.uuid4())
        }
        
        # 状态变量
        self.local_sequence = 0
        self.listen_state = None
        self.tts_state = None
        self.key_state = None
        self.conn_state = False
        self.restart_flag = False
        self.exit_flag = False
        self.auto_mode = False  # 新增：自动对话模式标志
        
        # 音频相关
        self.audio = None
        self.udp_socket = None
        self.mic = None
        self.mic_is_open = False
        self.spk = None
        self.encoder = None
        self.decoder = None
        
        # 线程
        self.recv_audio_thread = None
        self.send_audio_thread = None
        
        # MQTT客户端
        self.mqttc = None
        
        # 键盘监听器
        self.keyboard_listener = None
    
    def get_or_create_device_id(self):
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
    
    def initialize_audio(self):
        """初始化音频设备"""
        try:
            self.audio = pyaudio.PyAudio()
            
            # 检查音频设备
            if self.audio.get_default_input_device_info() is None:
                raise Exception("未检测到麦克风设备")
            if self.audio.get_default_output_device_info() is None:
                raise Exception("未检测到扬声器设备")
                
            # 初始化Opus编码器/解码器
            self.encoder = opuslib.Encoder(16000, 1, opuslib.APPLICATION_AUDIO)
            self.decoder = opuslib.Decoder(self.aes_opus_info['audio_params']['sample_rate'], 1)
            
            # 初始化UDP套接字
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
        except Exception as e:
            self.cleanup()
            raise Exception(f"音频初始化失败: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        try:
            if hasattr(self, 'mqttc') and self.mqttc:
                self.mqttc.loop_stop()
                self.mqttc.disconnect()
            
            self.stop_audio_threads()
            
            if self.audio:
                self.audio.terminate()
            
            if self.udp_socket:
                self.udp_socket.close()
                
        except Exception as e:
            print(f"{COLORS['ERROR']}清理资源时出错: {str(e)}{COLORS['RESET']}")
    
    def stop_audio_threads(self):
        """停止音频线程"""
        self.listen_state = "stop"
        
        if self.recv_audio_thread and self.recv_audio_thread.is_alive():
            self.recv_audio_thread.join(timeout=1)
        if self.send_audio_thread and self.send_audio_thread.is_alive():
            self.send_audio_thread.join(timeout=1)
            
        if self.mic and self.mic.is_open():
            self.mic.stop_stream()
            self.mic.close()
        if self.spk and self.spk.is_open():
            self.spk.stop_stream()
            self.spk.close()
    
    def get_ota_version(self):
        """获取OTA版本信息"""
        header = {
            'Device-Id': self.mac_addr,
            'Content-Type': 'application/json'
        }
        post_data = {
            "flash_size": 16777216,
            "minimum_free_heap_size": 8318916,
            "mac_address": f"{self.mac_addr}",
            "chip_model_name": "esp32s3",
            "chip_info": {"model": 9, "cores": 2, "revision": 2, "features": 18},
            "application": {
                "name": "xiaozhi",
                "version": "0.9.9",
                "compile_time": "Jan 22 2025T20:40:23Z",
                "idf_version": "v5.3.2-dirty",
                "elf_sha256": "22986216df095587c42f8aeb06b239781c68ad8df80321e260556da7fcf5f522"
            },
            "partition_table": [
                {"label": "nvs", "type": 1, "subtype": 2, "address": 36864, "size": 16384},
                {"label": "otadata", "type": 1, "subtype": 0, "address": 53248, "size": 8192},
                {"label": "phy_init", "type": 1, "subtype": 1, "address": 61440, "size": 4096},
                {"label": "model", "type": 1, "subtype": 130, "address": 65536, "size": 983040},
                {"label": "storage", "type": 1, "subtype": 130, "address": 1048576, "size": 1048576},
                {"label": "factory", "type": 0, "subtype": 0, "address": 2097152, "size": 4194304},
                {"label": "ota_0", "type": 0, "subtype": 16, "address": 6291456, "size": 4194304},
                {"label": "ota_1", "type": 0, "subtype": 17, "address": 10485760, "size": 4194304}
            ],
            "ota": {"label": "factory"},
            "board": {
                "type": "bread-compact-wifi",
                "ssid": "mzy",
                "rssi": -58,
                "channel": 6,
                "ip": "192.168.124.38",
                "mac": "cc:ba:97:20:b4:bc"
            }
        }

        try:
            response = requests.post(self.ota_version_url, headers=header, data=json.dumps(post_data))
            response.raise_for_status()
            self.mqtt_info = response.json()['mqtt']
            logging.info(f"get version: {response}")
        except Exception as e:
            raise Exception(f"获取OTA版本失败: {str(e)}")
    
    @staticmethod
    def aes_ctr_encrypt(key, nonce, plaintext):
        """AES CTR加密"""
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    
    @staticmethod
    def aes_ctr_decrypt(key, nonce, ciphertext):
        """AES CTR解密"""
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def send_audio(self):
        """发送音频数据"""
        key = bytes.fromhex(self.aes_opus_info['udp']['key'])
        nonce_base = bytes.fromhex(self.aes_opus_info['udp']['nonce'])
        server_ip = self.aes_opus_info['udp']['server']
        server_port = self.aes_opus_info['udp']['port']
        
        try:
            self.mic = self.audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=16000,
                input=True,
                frames_per_buffer=960
            )
            self.mic_is_open = True
            
            while not self.exit_flag:
                if self.listen_state == "stop" and not self.auto_mode:
                    time.sleep(0.1)
                    continue
                
                # 读取音频数据
                data = self.mic.read(960, exception_on_overflow=False)
                
                # 编码音频数据
                encoded_data = self.encoder.encode(data, 960)
                
                # 更新序列号并创建新的nonce
                self.local_sequence += 1
                new_nonce = (
                    nonce_base[0:4] + 
                    format(len(encoded_data), '04x').encode() + 
                    nonce_base[8:24] + 
                    format(self.local_sequence, '08x').encode()
                )
                
                # 加密数据
                encrypt_encoded_data = self.aes_ctr_encrypt(key, new_nonce, bytes(encoded_data))
                packet = new_nonce + encrypt_encoded_data
                
                # 发送数据
                self.udp_socket.sendto(packet, (server_ip, server_port))
                
        except Exception as e:
            print(f"{COLORS['ERROR']}发送音频错误：{str(e)}{COLORS['RESET']}")
        finally:
            self.local_sequence = 0
            # 查看可用属性和方法
            print(type(self.mic))
            print(dir(self.mic))
            # 手动维护开启音频标记
            if self.mic and self.mic_is_open:
                self.mic.stop_stream()
                self.mic.close()
    
    def recv_audio(self):
        """接收并播放音频数据"""
        key = bytes.fromhex(self.aes_opus_info['udp']['key'])
        nonce_base = bytes.fromhex(self.aes_opus_info['udp']['nonce'])
        sample_rate = self.aes_opus_info['audio_params']['sample_rate']
        frame_duration = self.aes_opus_info['audio_params']['frame_duration']
        frame_num = int(frame_duration / (1000 / sample_rate))
        
        try:
            self.spk = self.audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=sample_rate,
                output=True,
                frames_per_buffer=frame_num
            )
            
            while not self.exit_flag:
                data, _ = self.udp_socket.recvfrom(4096)
                
                # 解密数据
                split_nonce = data[:16]
                split_data = data[16:]
                decrypt_data = self.aes_ctr_decrypt(key, split_nonce, split_data)
                
                # 解码并播放
                decoded_data = self.decoder.decode(decrypt_data, frame_num)
                self.spk.write(decoded_data)
                
        except Exception as e:
            print(f"{COLORS['ERROR']}接收音频错误：{str(e)}{COLORS['RESET']}")
        finally:
            if self.spk and self.spk.is_open():
                self.spk.stop_stream()
                self.spk.close()
    
    def on_connect(self, client, userdata, flags, rs):
        """MQTT连接回调"""
        if rs != 0:
            print(f"{COLORS['ERROR']}❌ MQTT服务器连接失败，错误码：{rs}{COLORS['RESET']}")
            return
        
        # 订阅特定设备的主题
        subscribe_topic = f"{self.mqtt_info['subscribe_topic'].split('/')[0]}/p2p/GID_test@@@{self.mac_addr.replace(':', '_')}"
        client.subscribe(subscribe_topic)
    
    def restart_program(self):
        """重启程序"""
        if self.exit_flag:
            return
            
        self.restart_flag = True
        print(f"{COLORS['SYSTEM_STATUS']}🔄 正在重启应用...{COLORS['RESET']}")
        time.sleep(0.5)
        
        self.cleanup()
        
        # 重启进程
        python = sys.executable
        os.execl(python, python, *sys.argv)
    
    def on_key_press(self, key):
        """键盘按键处理"""
        try:
            if key == pynput_keyboard.Key.space:
                self.on_space_key_press()
            elif key == pynput_keyboard.Key.esc:
                self.exit_flag = True
                print(f"\n{COLORS['SYSTEM_STATUS']}👋 感谢使用小智语音助手，再见！{COLORS['RESET']}")
                return False
            elif hasattr(key, 'char') and key.char == 'r' and not self.exit_flag:
                self.restart_program()
            elif hasattr(key, 'char') and key.char == 't' and not self.exit_flag:
                self.toggle_auto_mode()
                
        except Exception as e:
            print(f"{COLORS['ERROR']}键盘监听错误: {str(e)}{COLORS['RESET']}")
        return True
    
    def on_key_release(self, key):
        """键盘释放处理"""
        if key == pynput_keyboard.Key.space:
            self.on_space_key_release()
    
    def toggle_auto_mode(self):
        """切换自动对话模式"""
        self.auto_mode = not self.auto_mode
        mode_name = "自动" if self.auto_mode else "手动"
        print(f"{COLORS['SYSTEM_STATUS']}🔄 已切换为{mode_name}对话模式{COLORS['RESET']}")
        
        if self.auto_mode:
            # 在自动模式下，立即开始监听
            self.start_listening()
        else:
            # 在手动模式下，停止监听
            self.stop_listening()
    
    def start_listening(self):
        """开始监听"""
        if self.conn_state is False or self.aes_opus_info['session_id'] is None:
            self.conn_state = True
            hello_msg = {
                "type": "hello",
                "version": 3,
                "transport": "udp",
                "audio_params": {
                    "format": "opus",
                    "sample_rate": 16000,
                    "channels": 1,
                    "frame_duration": 60
                }
            }
            self.push_mqtt_msg(hello_msg)
            print(f"{COLORS['SYSTEM_STATUS']}正在重新建立连接...{COLORS['RESET']}")
        
        if self.tts_state == "start" or self.tts_state == "sentence_start":
            self.push_mqtt_msg({"type": "abort"})
            print(f"{COLORS['SYSTEM_STATUS']}已中断当前播放{COLORS['RESET']}")
        
        if self.aes_opus_info['session_id'] is not None:
            msg = {
                "session_id": self.aes_opus_info['session_id'],
                "type": "listen",
                "state": "start",
                "mode": "auto" if self.auto_mode else "manual"
            }
            self.push_mqtt_msg(msg)
            self.listen_state = "start"
    
    def stop_listening(self):
        """停止监听"""
        if self.aes_opus_info['session_id'] is not None and self.listen_state == "start":
            msg = {
                "session_id": self.aes_opus_info['session_id'],
                "type": "listen",
                "state": "stop"
            }
            self.push_mqtt_msg(msg)
            self.listen_state = "stop"
    
    def on_space_key_press(self):
        """空格键按下处理"""
        if self.key_state == "press":
            return
            
        self.key_state = "press"
        print(f"{COLORS['SYSTEM_STATUS']}{ICONS['RECORDING']} 正在聆听...{COLORS['RESET']}")
        self.start_listening()
    
    def on_space_key_release(self):
        """空格键释放处理"""
        self.key_state = "release"
        print(f"{COLORS['SYSTEM_STATUS']}{ICONS['THINKING']} 正在处理...{COLORS['RESET']}")
        
        if not self.auto_mode:  # 只有在手动模式下才在释放时停止监听
            self.stop_listening()
    
    def push_mqtt_msg(self, message):
        """发送MQTT消息"""
        try:
            if self.mqttc and self.mqtt_info:
                self.mqttc.publish(self.mqtt_info['publish_topic'], json.dumps(message))
        except Exception as e:
            print(f"{COLORS['ERROR']}发送MQTT消息失败: {str(e)}{COLORS['RESET']}")
    
    def on_message(self, client, userdata, message):
        """MQTT消息处理"""
        try:
            msg = json.loads(message.payload)
            
            if msg['type'] == 'stt':
                print(f"{COLORS['USER_INPUT']}{ICONS['RECOGNIZED']} 已识别：{msg['text']}{COLORS['RESET']}")
            
            elif msg['type'] == 'tts':
                self.tts_state = msg['state']
                if msg['state'] == 'sentence_start':
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
                    # 播放结束后，如果是自动模式，继续监听
                    if self.auto_mode:
                        time.sleep(0.5)  # 短暂延迟后重新开始监听
                        self.start_listening()
            
            elif msg['type'] == 'llm':
                if 'emotion' in msg:
                    print(f"{COLORS['AI_RESPONSE']}{msg['text']} ({msg['emotion']}){COLORS['RESET']}")
            
            elif msg['type'] == 'hello':
                self.aes_opus_info = msg
                self.udp_socket.connect((msg['udp']['server'], msg['udp']['port']))
                
                if not self.recv_audio_thread or not self.recv_audio_thread.is_alive():
                    self.recv_audio_thread = threading.Thread(target=self.recv_audio, daemon=True)
                    self.recv_audio_thread.start()
                
                if not self.send_audio_thread or not self.send_audio_thread.is_alive():
                    self.send_audio_thread = threading.Thread(target=self.send_audio, daemon=True)
                    self.send_audio_thread.start()
            
            elif msg['type'] == 'goodbye' and self.udp_socket and msg['session_id'] == self.aes_opus_info['session_id']:
                self.aes_opus_info['session_id'] = None
                
        except Exception as e:
            print(f"{COLORS['ERROR']}处理MQTT消息时出错: {str(e)}{COLORS['RESET']}")
    
    def run(self):
        """主运行函数"""
        print(f"\n{COLORS['AI_RESPONSE']}欢迎使用小智语音助手！{COLORS['RESET']}")
        print(f"{COLORS['SYSTEM_STATUS']}系统正在初始化...{COLORS['RESET']}")
        
        try:
            self.initialize_audio()
            print(f"{COLORS['SYSTEM_STATUS']}正在连接服务器...{COLORS['RESET']}")
            self.get_ota_version()
            
            # 显示使用说明
            print(f"\n{COLORS['SYSTEM_STATUS']}✨ 系统已准备就绪！{COLORS['RESET']}")
            print(f"{COLORS['SYSTEM_STATUS']}📢 按住空格键开始对话（手动模式）{COLORS['RESET']}")
            print(f"{COLORS['SYSTEM_STATUS']}🔄 按T键切换自动/手动对话模式（当前：手动）{COLORS['RESET']}")
            print(f"{COLORS['SYSTEM_STATUS']}❌ 按ESC键退出程序 | 🔄 按R键重启程序{COLORS['RESET']}\n")
            
            # 启动键盘监听
            self.keyboard_listener = pynput_keyboard.Listener(
                on_press=self.on_key_press,
                on_release=self.on_key_release
            )
            self.keyboard_listener.start()
            
            # 创建MQTT客户端
            self.mqttc = mqtt.Client(client_id=self.mqtt_info['client_id'])
            self.mqttc.username_pw_set(username=self.mqtt_info['username'], password=self.mqtt_info['password'])
            self.mqttc.tls_set(
                ca_certs=None,
                certfile=None,
                keyfile=None,
                cert_reqs=mqtt.ssl.CERT_REQUIRED,
                tls_version=mqtt.ssl.PROTOCOL_TLS,
                ciphers=None
            )
            self.mqttc.on_connect = self.on_connect
            self.mqttc.on_message = self.on_message
            
            try:
                self.mqttc.connect(host=self.mqtt_info['endpoint'], port=8883)
                self.mqttc.loop_forever()
            except Exception as e:
                print(f"{COLORS['ERROR']}MQTT连接错误：{str(e)}{COLORS['RESET']}")
                
        except KeyboardInterrupt:
            print(f"\n{COLORS['SYSTEM_STATUS']}👋 感谢使用小智语音助手，再见！{COLORS['RESET']}")
        except Exception as e:
            print(f"{COLORS['ERROR']}系统错误：{str(e)}{COLORS['RESET']}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    try:
        assistant = XiaozhiAssistant()
        assistant.run()
    except Exception as e:
        print(f"{COLORS['ERROR']}程序启动失败：{str(e)}{COLORS['RESET']}")