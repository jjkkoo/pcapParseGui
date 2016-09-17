# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'pcapParseUi.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(798, 507)
        MainWindow.setAcceptDrops(True)
        MainWindow.setDocumentMode(False)
        MainWindow.setDockNestingEnabled(True)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.splitter = QtGui.QSplitter(self.centralwidget)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName(_fromUtf8("splitter"))
        self.tableWidget = QtGui.QTableWidget(self.splitter)
        self.tableWidget.setAutoFillBackground(True)
        self.tableWidget.setAlternatingRowColors(True)
        self.tableWidget.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.tableWidget.setObjectName(_fromUtf8("tableWidget"))
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.verticalLayout.addWidget(self.splitter)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.menuBar = QtGui.QMenuBar(MainWindow)
        self.menuBar.setGeometry(QtCore.QRect(0, 0, 798, 23))
        self.menuBar.setObjectName(_fromUtf8("menuBar"))
        self.menuFile = QtGui.QMenu(self.menuBar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        self.menuEdit = QtGui.QMenu(self.menuBar)
        self.menuEdit.setObjectName(_fromUtf8("menuEdit"))
        self.menuPlay = QtGui.QMenu(self.menuEdit)
        self.menuPlay.setObjectName(_fromUtf8("menuPlay"))
        self.menuModes = QtGui.QMenu(self.menuBar)
        self.menuModes.setObjectName(_fromUtf8("menuModes"))
        self.menuDebug_Mode = QtGui.QMenu(self.menuModes)
        self.menuDebug_Mode.setObjectName(_fromUtf8("menuDebug_Mode"))
        self.menuParse_Mode = QtGui.QMenu(self.menuModes)
        self.menuParse_Mode.setObjectName(_fromUtf8("menuParse_Mode"))
        MainWindow.setMenuBar(self.menuBar)
        self.actionPick_a_Pcap_File = QtGui.QAction(MainWindow)
        self.actionPick_a_Pcap_File.setObjectName(_fromUtf8("actionPick_a_Pcap_File"))
        self.actionExport_Selected_Line = QtGui.QAction(MainWindow)
        self.actionExport_Selected_Line.setObjectName(_fromUtf8("actionExport_Selected_Line"))
        self.actionExit = QtGui.QAction(MainWindow)
        self.actionExit.setObjectName(_fromUtf8("actionExit"))
        self.actionPlot_Selected_Stream = QtGui.QAction(MainWindow)
        self.actionPlot_Selected_Stream.setObjectName(_fromUtf8("actionPlot_Selected_Stream"))
        self.actionPlay_2 = QtGui.QAction(MainWindow)
        self.actionPlay_2.setObjectName(_fromUtf8("actionPlay_2"))
        self.actionStop = QtGui.QAction(MainWindow)
        self.actionStop.setObjectName(_fromUtf8("actionStop"))
        self.actionDebug = QtGui.QAction(MainWindow)
        self.actionDebug.setCheckable(True)
        self.actionDebug.setObjectName(_fromUtf8("actionDebug"))
        self.actionInfo = QtGui.QAction(MainWindow)
        self.actionInfo.setCheckable(True)
        self.actionInfo.setChecked(True)
        self.actionInfo.setObjectName(_fromUtf8("actionInfo"))
        self.actionIPS_original = QtGui.QAction(MainWindow)
        self.actionIPS_original.setCheckable(True)
        self.actionIPS_original.setChecked(True)
        self.actionIPS_original.setObjectName(_fromUtf8("actionIPS_original"))
        self.actionOptimised = QtGui.QAction(MainWindow)
        self.actionOptimised.setCheckable(True)
        self.actionOptimised.setEnabled(False)
        self.actionOptimised.setObjectName(_fromUtf8("actionOptimised"))
        self.menuFile.addAction(self.actionPick_a_Pcap_File)
        self.menuFile.addAction(self.actionExit)
        self.menuPlay.addAction(self.actionPlay_2)
        self.menuPlay.addAction(self.actionStop)
        self.menuEdit.addAction(self.actionPlot_Selected_Stream)
        self.menuEdit.addAction(self.actionExport_Selected_Line)
        self.menuEdit.addAction(self.menuPlay.menuAction())
        self.menuDebug_Mode.addAction(self.actionDebug)
        self.menuDebug_Mode.addAction(self.actionInfo)
        self.menuDebug_Mode.addSeparator()
        self.menuParse_Mode.addAction(self.actionIPS_original)
        self.menuParse_Mode.addAction(self.actionOptimised)
        self.menuModes.addAction(self.menuDebug_Mode.menuAction())
        self.menuModes.addAction(self.menuParse_Mode.menuAction())
        self.menuBar.addAction(self.menuFile.menuAction())
        self.menuBar.addAction(self.menuEdit.menuAction())
        self.menuBar.addAction(self.menuModes.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
        self.tableWidget.setSortingEnabled(False)
        self.menuFile.setTitle(_translate("MainWindow", "File", None))
        self.menuEdit.setTitle(_translate("MainWindow", "Edit", None))
        self.menuPlay.setTitle(_translate("MainWindow", "Play", None))
        self.menuModes.setTitle(_translate("MainWindow", "Modes", None))
        self.menuDebug_Mode.setTitle(_translate("MainWindow", "Debug Mode", None))
        self.menuParse_Mode.setTitle(_translate("MainWindow", "Parse Mode", None))
        self.actionPick_a_Pcap_File.setText(_translate("MainWindow", "Pick a Pcap File", None))
        self.actionPick_a_Pcap_File.setShortcut(_translate("MainWindow", "F4", None))
        self.actionExport_Selected_Line.setText(_translate("MainWindow", "Export", None))
        self.actionExport_Selected_Line.setShortcut(_translate("MainWindow", "F6", None))
        self.actionExit.setText(_translate("MainWindow", "Exit", None))
        self.actionPlot_Selected_Stream.setText(_translate("MainWindow", "Plot", None))
        self.actionPlot_Selected_Stream.setShortcut(_translate("MainWindow", "F5", None))
        self.actionPlay_2.setText(_translate("MainWindow", "Play/Pause/Resume", None))
        self.actionPlay_2.setShortcut(_translate("MainWindow", "Space", None))
        self.actionStop.setText(_translate("MainWindow", "Stop", None))
        self.actionStop.setShortcut(_translate("MainWindow", "F9", None))
        self.actionDebug.setText(_translate("MainWindow", "Debug", None))
        self.actionInfo.setText(_translate("MainWindow", "Info", None))
        self.actionIPS_original.setText(_translate("MainWindow", "IPS original", None))
        self.actionOptimised.setText(_translate("MainWindow", "optimised", None))

