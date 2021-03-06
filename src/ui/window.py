"""Main repator window creator."""

# coding=utf-8
from collections import OrderedDict
from copy import copy

from PyQt5.QtWidgets import QWidget, QTabWidget, QPushButton, QGridLayout, QFileDialog, QMessageBox, \
    QApplication
from PyQt5.QtCore import QCoreApplication, Qt

from conf.ui_vulns_initial import VULNS_INITIAL, add_vuln_initial
from conf.ui_auditors_initial import AUDITORS_INITIAL, add_auditor_initial
from conf.report import GIT
from src.dbhandler import DBHandler
from src.reportgenerator import json, Generator
from src.ui.tab import Tab
from src.ui.objects_git import ObjectsGit
from src.git_interactions import Git
from src.ui.diff_window import DiffWindows

class Window(QWidget):
    """Repator window creation class."""

    def __init__(self, title, tab_lst):
        super().__init__()

        self.app = QCoreApplication.instance()
        self.git = self.app.findChild(Git)

        self.setWindowTitle(title)
        self.setContentsMargins(0, 0, 0, 0)

        tabw = QTabWidget()
        self.tabs = {}
        self.tab_is_modified = {}

        for label, tab in tab_lst.items():
            if "add_fct" in tab:
                self.tabs[label] = Tab(
                    tabw, tab["lst"], tab["db"], tab["add_fct"])
            elif "db" in tab:
                self.tabs[label] = Tab(tabw, tab["lst"], tab["db"])
            else:
                self.tabs[label] = Tab(tabw, tab)
            self.tabs[label].updateField.connect(self.set_modified)
            tabw.addTab(self.tabs[label], label)

        save_btn = QPushButton("Save", self)
        save_btn.clicked.connect(self.save)
        load_btn = QPushButton("Load", self)
        load_btn.clicked.connect(self.load)
        view_changes_btn = QPushButton("View Changes", self)
        view_changes_btn.clicked.connect(self.view_changes)
        generate_btn = QPushButton("Generate", self)
        generate_btn.clicked.connect(self.generate)
        git_text = QPushButton("Git : " + GIT, self)
        # git_text is connected when git process is running

        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(5, 5, 5, 5)

        self.grid.addWidget(tabw, 0, 0, 1, 5)
        self.grid.addWidget(save_btn, 1, 0)
        self.grid.addWidget(load_btn, 1, 1)
        self.grid.addWidget(view_changes_btn, 1, 2)
        self.grid.addWidget(generate_btn, 1, 3)
        self.grid.addWidget(git_text, 1, 4)

        self.setLayout(self.grid)

    def load_json(self, json_str):
        """Transforms a json string into a dict and sends it to next loader."""
        self.load_dict(json.loads(json_str))

    def load_dict(self, values):
        """Loads the different tabs."""
        for tabname, tabval in values.items():
            self.tabs[tabname].load(tabval)

    def load(self):
        """Pops the load window."""
        project_filename = QFileDialog.getOpenFileName(
            self, "Load Repator Project", "projects/",
            "Repator Project files [*.rep] (*.rep);;All files [*] (*)")[0]
        if project_filename:
            try:
                with open(project_filename, 'r') as project_file:
                    self.load_json(project_file.read())
                    self.set_modified(None, False)
            except (KeyError, TypeError, json.decoder.JSONDecodeError):
                print("LoadFileError")

    def save(self):
        """Pops the save window."""
        values = {}
        for tabname, tab in self.tabs.items():
            values[tabname] = tab.save(database=True)
        project_filename = QFileDialog.getSaveFileName(
            self, "Save Repator Project", "projects/test.rep",
            "Repator Project files [*.rep] (*.rep);;All files [*] (*)")[0]
        if project_filename:
            with open(project_filename, 'w') as project_file:
                project_file.write(json.dumps(values))
                self.set_modified(None, False)
                return True
        return False

    def generate(self):
        """Launches the docx report generation."""
        values = {}
        for tabname, tab in self.tabs.items():
            values[tabname] = tab.save(database=False)

        # Adding images in values to generation
        lst = self.tabs["Vulns"].lst["vulns"]["arg"][0]
        for idents, elem in lst.items():
            field = idents.split("-")
            if len(field) > 1 and field[1] in values["Vulns"]:
                if "imagesPath" in field[0]:
                    values["Vulns"][field[1]]["imagesPath"] = elem

                if "imagesText" in field[0]:
                    values["Vulns"][field[1]]["imagesText"] = elem

                if "imagesHistory" in field[0]:
                    values["Vulns"][field[1]]["imagesHistory"] = elem

        # Removing db from values
        for name, value in values.items():
            if "db" in value:
                del values[name]["db"]

        output_filename = QFileDialog.getSaveFileName(
            self, "Generate Report", "output.docx",
            "Microsoft Document [*.docx] (*.docx);;All files [*] (*)")[0]

        if output_filename:
            Generator.generate_all(values, output_filename)
            self.set_modified(None, False)

    def view_changes(self):
        """Opens the window "Diffs"."""
        # NB: the windows "Diffs" will close when editing in "Repator" if
        # nothing has been opened in it.
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Diffs" and window.isVisible():
                self.app.setActiveWindow(window)
                window.tabw.setCurrentIndex(self.tabs["Mission"]._parent.currentIndex() % 3)
                return
        window = DiffWindows()
        window.tabw.setCurrentIndex(self.tabs["Mission"]._parent.currentIndex() % 3)
        window.showMaximized()

    def set_modified(self, tab, value):
        if tab is None:
            self.tab_is_modified.clear()
        else:
            self.tab_is_modified[tab] = value

    def closeEvent(self, event):
        have_been_modified = False
        for value in self.tab_is_modified.values():
            if value:
                have_been_modified = True

        if have_been_modified:
            close = QMessageBox.question(self,
                                         "QUIT",
                                         "Changes have been occurred.\nDo you want to quit without saving?",
                                         QMessageBox.Yes | QMessageBox.Save | QMessageBox.No)
        try:
            if not have_been_modified or close == QMessageBox.Yes:
                QApplication.instance().closeAllWindows()
            elif close == QMessageBox.Save:
                if not self.save():
                    self.tab_is_modified["dataNotSaved"] = True
                    event.ignore()
                else:
                    QApplication.instance().closeAllWindows()
            else:
                event.ignore()
        except:
            pass
