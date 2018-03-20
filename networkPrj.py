import sys,packetParsing
from PyQt5.QtWidgets import ( QGroupBox, QComboBox, QWidget, QLabel, QLineEdit,
    QTextEdit, QGridLayout, QApplication,QPushButton,QDialog,QCheckBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont,QCursor,QIntValidator,QColor

 
class network(QDialog):
     
    def __init__(self):
        super().__init__()
         
        self.initUI()
         
         
    def initUI(self):
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setStyleSheet("background-color: skyblue")

        qgb = QGroupBox('数据包解析工具',self)
        qgb.setFont(QFont("Timers", 8, QFont.Bold))
        qgb.move(20,20)
        qgb.minimumSizeHint()

        qgb.setStyleSheet(
          "QGroupBox"
          "{"
          "border: 1px solid white;"
          "border-radius:8px;"
          "margin-top:6px;"
          "}"
          "QGroupBox:title"
          "{"
          "color:white;"
          "subcontrol-origin: margin;"
          "left: 10px;"
          "}"
          )

        lbPort = QLabel('Port(0-65565):',qgb)
        lbTime = QLabel('Time(s):',qgb)
        lbProtocal = QLabel('protocal:',qgb)
        
        self.cb = QCheckBox('混淆模式',qgb)
        self.cb.toggle()
        self.cb.setCheckState(False)
        self.cb.stateChanged.connect(self.editEnable)

        self.portEdit = QLineEdit('65565',qgb)
        self.portEdit.setMaximumWidth(50)
        self.portEdit.setValidator(QIntValidator(0, 65565, self))
        self.timeEdit = QLineEdit('10',qgb)
        self.timeEdit.setMaximumWidth(50)
        self.timeEdit.setValidator(QIntValidator(1, 100, self))

        self.combo = QComboBox(qgb)
        self.combo.addItem("所有")
        self.combo.addItem("TCP")
        self.combo.addItem("UDP")
        self.combo.addItem("ICMP")

                                   
        okButton = QPushButton("start",qgb)
        cancelButton = QPushButton("cancel",qgb)

        okButton.clicked.connect(self.start)           
        cancelButton.clicked.connect(self.close)

        lbPort.move(10,35)
        self.portEdit.move(130,33)
        self.cb.move(130,59)


        lbTime.move(10,88)
        self.timeEdit.move(130,86)

        lbProtocal.move(10,116)
        self.combo.move(130,114)

        okButton.move(20,150)
        cancelButton.move(120,150)

        self.portEdit.setStyleSheet("background-color:rgb(255,255,255)")
        self.timeEdit.setStyleSheet("background-color:rgb(255,255,255)")
        self.combo.setStyleSheet("background-color:rgb(255,255,255)")
    
        self.setGeometry(300, 300, 280, 250)
        self.setWindowTitle('Packet Parsing')   
        self.show()

    def start(self):
        pp = packetParsing.packetParsing(self.portEdit.text(),self.timeEdit.text(),self.cb.checkState())

    def editEnable(self,state):
        if state == Qt.Checked:
            self.portEdit.setReadOnly(True)
            self.temp = self.portEdit.text()
            self.portEdit.setText('')
            self.portEdit.setStyleSheet("background-color:rgb(192,192,192)")
        else:
            self.portEdit.setReadOnly(False)
            self.portEdit.setText(self.temp)
            self.portEdit.setStyleSheet("background-color:rgb(255,255,255)")

    def mousePressEvent(self, event):
        if event.button()==Qt.LeftButton:
            self.m_drag=True
            self.m_DragPosition=event.globalPos()-self.pos()
            event.accept()
           # self.setCursor(QCursor(Qt.OpenHandCursor))
           
    def mouseMoveEvent(self, QMouseEvent):
        if Qt.LeftButton and self.m_drag:
            self.move(QMouseEvent.globalPos()-self.m_DragPosition)
            QMouseEvent.accept()

    def mouseReleaseEvent(self, QMouseEvent):
        self.m_drag=False
        self.setCursor(QCursor(Qt.ArrowCursor))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = network()
    sys.exit(app.exec_())