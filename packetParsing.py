from __future__ import division
import sys,struct,socket,threading,time
import IPclass
from struct import *
from time import ctime,sleep
from os import system

from PyQt5.QtWidgets import (QToolTip, QGroupBox,QHeaderView,QAbstractItemView,QTableWidget, QTableWidgetItem, QMainWindow, QWidget, QLabel, QLineEdit,
    QTextEdit, QGridLayout, QApplication,QPushButton,QDialog)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

import numpy as np
import matplotlib.pyplot as plt

class packetParsing(QMainWindow):

    def __init__(self,port,time,promiscuousMode):
        super().__init__()
        if port=='':
            self.p=65565
        else:
            self.p=int(port)
        self.t=int(time)
        self.pm=int(promiscuousMode)

        system('sniffer')
        self.initUI()
        self.run=True

        #多线程以计时监听
        threads = []
        t1 = threading.Thread(target = self.timing)
        t2 = threading.Thread(target = self.parsing)

        t2.setDaemon(True)  #解析为后台
        threads.append(t1)
        threads.append(t2)
        for t in threads:
            t.start()

    def initUI(self):
        self.sbar = self.statusBar()
        self.sbar.showMessage('Ready')
        self.qtw = QTableWidget(0,12)
        self.setGeometry(300, 300, 1050, 200)#大小位置
        #粗体头
        qf = self.qtw.horizontalHeader().font()
        qf.setBold(True)
        self.qtw.horizontalHeader().setFont(qf)
        self.qtw.horizontalHeader().setStretchLastSection(True)#拉伸   
        self.qtw.setEditTriggers(QAbstractItemView.NoEditTriggers)#禁止编辑
        self.qtw.verticalHeader().setDefaultSectionSize(25)#行高
        self.qtw.horizontalHeader().setStyleSheet("QHeaderView::section{background:skyblue;}")#QSS
        self.qtw.setShowGrid(False)#不显示格子线
        self.qtw.setHorizontalHeaderLabels(['time','ver','ihl','tos','总长度','id','offset','TTL','校验和','源IP','目的IP','协议'])
        self.qtw.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.qtw.setStyleSheet("selection-background-color:lightblue;")

        self.qtw.setColumnWidth(0,200)
        self.qtw.setColumnWidth(1,40)
        self.qtw.setColumnWidth(2,40)
        self.qtw.setColumnWidth(3,40)
        self.qtw.setColumnWidth(4,60)
        self.qtw.setColumnWidth(5,60)
        self.qtw.setColumnWidth(6,60)
        self.qtw.setColumnWidth(7,60)
        self.qtw.setColumnWidth(8,80)
        self.qtw.setColumnWidth(9,135)
        self.qtw.setColumnWidth(10,135)                                                                                                                                                                                                                                                                                                                                  
        self.qtw.setColumnWidth(11,60)

        self.qtw.horizontalScrollBar().setStyleSheet(
          "QScrollBar{background:transparent; height:15px;}"
          "QScrollBar::handle{background:lightgray; border:5px solid transparent; border-radius:5px;}"
          "QScrollBar::handle:hover{background:gray;}"
          "QScrollBar::sub-line{background:transparent;}"
          "QScrollBar::add-line{background:transparent;}")

        self.qtw.setAlternatingRowColors(True)

        self.setCentralWidget(self.qtw)
        self.show()
        self.num = 0

    def timing(self):
        self.nps = 0
        self.plotData=[]
        num0 = 0    
        for sec in range(self.t):
            time.sleep(1)
            self.nps = self.num - num0
            self.sbar.showMessage(str(9-sec)+' second left...  '+str(self.nps)+ ' packets/s')
            self.plotData.extend([self.nps])
            num0 = self.num           

        self.run=False
        self.s.close()
        self.sbar.showMessage('timing ends')

    def parsing(self):

        #返回对应于给定主机名的包含主机名字和地址信息的hostent结构的指针。结构的声明与gethostbyaddr()中一致。
        HOST = socket.gethostbyname(socket.gethostname())
        # create a raw socket and bind it to the public interface
        #地址族(Internet 进程间通信)，原始套接字，ip协议
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.s.bind((HOST, 0))

        # 包括IP头
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # 混淆模式
        if self.pm==2:
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.num_tcp = 0
        self.num_udp = 0
        self.num_icmp = 0
        self.num_other = 0

        while self.run==True:
            
            try:
                packet = self.s.recvfrom(self.p)
            except OSError:
                break
            packet = packet[0]

            ip_header = IPclass.IP(packet[0:20])
            ihl = ip_header.ihl * 4
            version = ip_header.version
            tos = ip_header.tos
            iph_length = ip_header.len
            identifier = ip_header.id
            offset = ip_header.offset
            csum = ip_header.sum
            ttl = ip_header.ttl
            protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
            try:
            	protocol = protocol_map[ip_header.protocol_num]
            except KeyError:
            	break
            ip_checksum = ip_header.sum
            s_addr = ip_header.src_address #源IP
            d_addr = ip_header.dst_address #目的IP           
            '''
            #手动解析
            ip_header = packet[0:20]
            iph = unpack('!BBHHHBBH4s4s',ip_header)
            version = iph[0] >> 4 #版本(ipv?)
            ihl = iph[0] * 0xF  #IHL(ip头长)
            iph_length = ihl * 4  #ip头*4？
            ttl = iph[5]  #生存时间
            protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
            protocol_num =iph[6] #协议类型（tcp,udp....)
            protocol = protocol_map[protocol_num]
            ip_checksum = iph[7]
            s_addr = socket.inet_ntoa(iph[8]) #源IP
            d_addr = socket.inet_ntoa(iph[9]) #目的IP
            '''
            self.qtw.insertRow(self.num)
            item = QTableWidgetItem(ctime())#时间
            self.qtw.setItem(self.num,0,item)

            item = QTableWidgetItem(str(version))#版本
            self.qtw.setItem(self.num,1,item)

            item = QTableWidgetItem(str(ihl))#头长度(Internet Header Length)
            self.qtw.setItem(self.num,2,item)

            item = QTableWidgetItem(str(tos))#服务类型
            self.qtw.setItem(self.num,3,item)

            item = QTableWidgetItem(str(iph_length))#total length
            self.qtw.setItem(self.num,4,item)

            item = QTableWidgetItem(str(identifier))#标识符
            self.qtw.setItem(self.num,5,item)

            item = QTableWidgetItem(str(offset))#分段偏移
            self.qtw.setItem(self.num,6,item)

            item = QTableWidgetItem(str(ttl))#生存时间
            self.qtw.setItem(self.num,7,item)

            item = QTableWidgetItem(str(csum))#头校验和
            self.qtw.setItem(self.num,8,item)   

            item = QTableWidgetItem(str(s_addr))#源ip
            self.qtw.setItem(self.num,9,item)

            item = QTableWidgetItem(str(d_addr))#目的ip
            self.qtw.setItem(self.num,10,item)

            item_p = QTableWidgetItem(str(protocol))#协议类型           
            self.qtw.setItem(self.num,11,item_p)

            self.num+=1

            #tcp报文
            if ip_header.protocol_num == 6:
                self.num_tcp+=1
                tcp_header = packet[20:40]
                tcph = unpack('!HHLLBBHHH' , tcp_header)
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                data = packet[40:len(packet)]
                item_p.setToolTip('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length) + '\nData : ' + str(data))
                print(str(self.num)+ctime())    
                print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
                print ('Data : ' + str(data))

            #udp报文
            elif ip_header.protocol_num == 17:
                self.num_udp+=1
                udp_header = packet[20:28]
                udph = unpack('!HHHH' , udp_header)
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                data = packet[28:len(packet)]
                item_p.setToolTip('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum) + '\nData : ' + str(data))
                print(str(self.num)+ctime())  
                print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
                print ('Data : ' + str(data))

            #icmp报文，用来传递查询报文与差错报文的一种协议
            elif ip_header.protocol_num ==1:
                self.num_icmp+=1
                icmp_length = 4
                icmp_header = packet[20:20+ 4]
                icmph = unpack('!BBH' , icmp_header)
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
                item_p.setToolTip('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' +str(checksum))
                print(str(self.num)+ctime())
                print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' +str(checksum))

            else :
                item_p.setToolTip('不能解析')
                self.num_other+=1

        # disabled promiscuous mode
        print('end')
        self.showChart()
        sleep(1000)
    
    def showChart(self):
        plt.figure(figsize=(12,6),dpi=80) 
        labels = 'TCP', 'UDP', 'ICMP', 'Others'
        print(self.num_tcp, self.num_udp,self.num_icmp,self.num_other)
        if self.num != 0:
            fracs = [self.num_tcp/self.num,  self.num_udp/self.num,  self.num_icmp/self.num,  self.num_other/self.num]
       	else:
       		fracs=[0,0,0,0]
        explode = [0, 0.1, 0.2, 0.3] # 0.1 凸出这部分，
        plt.axes(aspect=1)  # set this , Figure is round, otherwise it is an ellipse
        #autopct ，show percet
        plt.subplot(121)
        plt.pie(x=fracs, labels=labels, explode=explode,autopct='%3.1f %%',
                shadow=True, labeldistance=1.1, startangle = 90,pctdistance = 0.6)
        '''
        labeldistance，文本的位置离远点有多远，1.1指1.1倍半径的位置
        autopct，圆里面的文本格式，%3.1f%%表示小数有三位，整数有一位的浮点数
        shadow，饼是否有阴影
        startangle，起始角度，0，表示从0开始逆时针转，为第一块。一般选择从90度开始比较好看
        pctdistance，百分比的text离圆心的距离
        patches, l_texts, p_texts，为了得到饼图的返回值，p_texts饼图内部文本的，l_texts饼图外label的文本
        '''

        plt.subplot(122)
        plt.plot(range(self.t),self.plotData)
        plt.xlabel('time(s)')
        plt.ylabel('packets')
        plt.show()