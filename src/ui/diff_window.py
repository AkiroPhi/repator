"""Windows for Diff"""

# coding=utf-8
from PyQt5.QtWidgets import QTabWidget, QGridLayout, QLabel, QWidget, QPushButton, QScrollArea
from PyQt5.QtCore import QCoreApplication
from copy import copy

from conf.ui_auditors_initial import AUDITORS_INITIAL, add_auditor_initial
from conf.ui_vulns_initial import VULNS_INITIAL, add_vuln_initial
from src.ui.tab import Tab
from src.ui.objects_git import ObjectsGit
from src.dbhandler import DBHandler
from src.git_interactions import Git



class DiffWindows(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Diffs")
        self.app = QCoreApplication.instance()
        self.git = self.app.findChild(Git)

        self.init_tab()
        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(5, 5, 5, 5)
        self.grid.addWidget(self.tabw, 0,0,1,-1)

        self.setLayout(self.grid)
        self.grid.addWidget(QPushButton("Refresh"), 1, 0)
        self.grid.itemAt(1).widget().clicked.connect(self.git.refresh) # the function refresh_tab after refresh git

    def init_tab(self):
        self.tabw = QTabWidget()
        tab_lst = copy(VULNS_INITIAL), DBHandler.vulns(
        ), DBHandler.vulns_git(), add_vuln_initial
        obj = ObjectsGit("vulns", tab_lst, self)
        self.tabw.addTab(obj, "Vulns")

        tab_lst = copy(AUDITORS_INITIAL), DBHandler.auditors(), DBHandler.auditors_git(), add_auditor_initial
        obj = ObjectsGit("auditors", tab_lst, self)
        self.tabw.addTab(obj, "Auditors")

        tab_lst = copy(AUDITORS_INITIAL), DBHandler.clients(), DBHandler.clients_git(), add_auditor_initial
        obj = ObjectsGit("clients", tab_lst, self)
        self.tabw.addTab(obj, "Clients")


    def refresh_tab_widget(self):
        """Refresh all the ObjectGit in the window"""
        for i in range(self.tabw.count()):
            self.tabw.widget(i).refresh_tab_widget()
