import socket  
import os   
import struct  
from ctypes import *  
  
#IP头定义，C类型的数组，结构化数据串行处理
class IP(Structure):  
    _fields_ = [  
        ("ihl",           c_ubyte, 4),  
        ("version",       c_ubyte, 4),  
        ("tos",           c_ubyte),  
        ("len",           c_ushort),  
        ("id",            c_ushort),  
        ("offset",        c_ushort),  
        ("ttl",           c_ubyte),  
        ("protocol_num",  c_ubyte),  
        ("sum",           c_ushort),  
        ("src",           c_ulong),  
        ("dst",           c_ulong)  
    ]

    #使用from_buffer_copy方法在__new__方法将收到的数据生成一个IP class的实例
    def __new__(self,socket_buffer=None):  
        return self.from_buffer_copy(socket_buffer) 
          
    def __init__(self, socket_buffer=None):  
  
        # map protocol constants to their names  
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}  
  
        # human readable IP addresses
        #inet_ntoa 将一个十进制网络字节序转换为点分十进制IP格式的字符串。
        #pack 按照给定的格式("<L")，把数据封装成字符串(实际上是类似于c结构体的字节流)
        #<L little-endian      unsigned long
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))  
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))  
  
        # human readable protocol  
        try:  
            self.protocol = self.protocol_map[self.protocol_num]  
        except:  
            self.protocol = str(self.protocol_num) 
