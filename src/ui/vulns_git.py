"""Defines the features used for the "Diffs" window."""

# coding=utf-8

from collections import OrderedDict
import json
from copy import copy

from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QCoreApplication
from PyQt5.QtWidgets import (QWidget, QTabWidget, QGridLayout, QTabBar,
                             QPushButton, QLabel, QComboBox, QMessageBox)

from conf.ui_vuln_changes import vuln_changes
from conf.ui_vulns_initial import VULNS_INITIAL
from conf.ui_vulns import VULNS
from conf.report import LANGUAGES, GREEN, RED, BLUE, DEFAULT, COLORS, HEADERS, CVSS, HISTORIES
from conf.db import DB_VULNS_GIT, DB_VULNS, DB_VULNS_GIT_UPDATED
from src.cvss import cvssv3, risk_level
from src.git_interactions import Git
from src.ui.checks_window import GitButton
from src.ui.tab import Tab


from src.dbhandler import DBHandler


class VulnsGit(QWidget):
    """Class for the features of the "Diffs" window."""

    def __init__(self, title, args):
        super().__init__()

        self.app = QCoreApplication.instance()
        self.git = self.app.findChild(Git)

        self.lst = args[0]
        self.db_initial = args[1]
        self.db_git = args[2]
        self.add_fct = args[3]
        self.hide = False
        self.buttons = dict()
        self.hidden_vulns = self.git.hidden_changes_vulns # using reference
        self.json_db_git = dict()
        self.json_db = dict()

        self.setWindowTitle(title)

        self.init_tab()
        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(5, 5, 5, 5)
        self.grid.addWidget(self.tabw, 0, 0, 1, -1)

        self.setLayout(self.grid)
        self.init_bottom_buttons()
        self.grid.itemAt(0).widget().currentChanged.connect(
            self.change_bottom_buttons)

    def init_tab(self):
        """Tab widget initialization."""
        self.tabw = QTabWidget()
        self.tabw.setTabsClosable(True)
        self.tabw.tabCloseRequested.connect(self.close_tab)
        self.tabs = {}

        tab_lst = OrderedDict()
        tab_lst["All"] = self.lst

        self.init_db_local_git()
        self.update_diffs()

        for label, lst in tab_lst.items():
            self.add_tab(label, lst, self.db_initial, self.add_fct)

        # Remove close button for the first tab ("All")
        self.tabw.tabBar().setTabButton(0, QTabBar.RightSide, None)
        self.tabw.tabBar().setTabButton(0, QTabBar.LeftSide, None)

        self.update_status()
        self.tabs["All"].fields["categorySort"].init_sorts()
        self.tabw.widget(0).widget.layout().itemAt(
            3).widget().clicked.connect(self.git_refresh)

    def add_tab(self, label, lst, database, add_fct=None):
        """Method to add a tab to the VulnsGit tab widget."""
        if label in self.tabs:
            for i in range(self.tabw.count()):
                if self.tabw.tabText(i) == label:
                    self.tabw.setCurrentWidget(self.tabw.widget(i))
                    return
        else:
            if label == "All":
                self.add_changed_entries(lst)
            if label == "All" or len(LANGUAGES) == 1:
                self.tabs[label] = Tab(self, lst, self.add_fct)
                self.tabw.addTab(self.tabs[label], label)
                self.tabw.setCurrentWidget(self.tabs[label])
            else:
                tabw = QTabWidget()
                tabs = OrderedDict()
                for lang in LANGUAGES:
                    tabs[lang] = Tab(self, lst[lang], database, add_fct)
                    tabw.addTab(tabs[lang], lang)
                self.tabs[label] = tabs
                self.tabw.addTab(tabw, label)
                self.tabw.setCurrentWidget(tabw)
            if label != "All":
                if len(LANGUAGES) == 1:
                    VulnsGit.init_history_color(self.tabs[label], label)
                    self.update_cvss_metrics(label, self.tabs[label])
                else:
                    for lang in self.tabs[label]:
                        VulnsGit.init_history_color(lang,
                            self.tabs[label][lang], label)
                        self.update_cvss_metrics(label, self.tabs[label][lang])

    def init_bottom_buttons(self):
        """Creates the buttons at the bottom of the window "Diffs"."""
        self.buttons["uploadBtn"] = GitButton("Upload changes", "upload", self)
        self.buttons["hideBtn"] = GitButton("Hide changes", "hide", self)
        self.buttons["patchBtn"] = GitButton("Patch", "patch", self)

        self.buttons["hideOneBtn"] = QPushButton("Hide changes for this vuln")
        self.buttons["patchOneBtn"] = QPushButton("Patch this vuln")
        self.buttons["duplicateOneButton"] = QPushButton("Duplicate this vuln")
        self.buttons["uploadOneBtn"] = QPushButton("Upload this vuln")

        # self.buttons["uploadBtn"].clicked.connect(self.upload_changes)
        # self.buttons["hideBtn"].clicked.connect(self.hide_changes)
        # self.buttons["patchBtn"].clicked.connect(self.patch_changes)
        self.buttons["hideOneBtn"].clicked.connect(self.hide_one_change)
        self.buttons["patchOneBtn"].clicked.connect(self.patch_one_change)
        self.buttons["duplicateOneButton"].clicked.connect(self.duplicate_one_vuln)
        self.buttons["uploadOneBtn"].clicked.connect(self.upload_one_change)
        self.grid.addWidget(QWidget(), 1, 0)
        self.grid.addWidget(QWidget(), 1 ,0)

        bottomButton = QGridLayout()
        bottomButton.setSpacing(5)
        bottomButton.setContentsMargins(5, 5, 5, 5)

        bottomButton.addWidget(self.buttons["uploadBtn"], 0, 0)
        bottomButton.addWidget(self.buttons["hideBtn"], 0, 1)
        bottomButton.addWidget(self.buttons["patchBtn"], 0, 2)
        self.grid.itemAt(1).widget().setLayout(bottomButton)

        bottomButton = QGridLayout()
        bottomButton.setSpacing(5)
        bottomButton.setContentsMargins(5, 5, 5, 5)

        bottomButton.addWidget(self.buttons["uploadOneBtn"], 0, 0)
        bottomButton.addWidget(self.buttons["hideOneBtn"], 0, 1)
        bottomButton.addWidget(self.buttons["patchOneBtn"], 0, 2)
        bottomButton.addWidget(self.buttons["duplicateOneButton"], 0, 3)
        self.grid.itemAt(2).widget().setLayout(bottomButton)


        self.show_buttons_all_view()

    def change_bottom_buttons(self):
        """Triggers hiding and showing of "Diffs" bottom buttons."""
        index = self.grid.itemAt(0).widget().currentIndex()
        if not index:
            self.show_buttons_all_view()
        else:
            ident = self.tabw.tabText(index)
            self.show_buttons_changes_view(self.style[ident] == BLUE)

    def show_buttons_all_view(self):
        """Shows the buttons that have to be displayed when in the tab "All"."""
        self.grid.itemAt(2).widget().hide()
        self.grid.itemAt(1).widget().show()


    def show_buttons_changes_view(self, duplicate):
        """Shows the buttons that have to be displayed when in any tab but "All"."""
        self.grid.itemAt(1).widget().hide()
        self.grid.itemAt(2).widget().show()
        self.buttons["duplicateOneButton"].setEnabled(duplicate)


    def duplicate_one_vuln(self):
        """Duplicate one vuln"""
        index = self.tabw.currentIndex()
        ident = self.tabw.tabText(index)
        new_ident = max([int(x) for x in list(self.json_db.keys()) + list(self.json_db_git.keys()) ]) + 1
        jsondb = "{\"_default\":" + \
            json.dumps({(new_ident if x == ident else int(x)): self.json_db[x]
                        for x in self.json_db.keys()}, sort_keys=True) + "}"
        with open(DB_VULNS, 'w') as output:
            output.write(jsondb)
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
        self.refresh_repator(repator)
        self.update_diffs()
        self.refresh_tab_widget()
        self.close_tab(index)


    def upload_changes(self, checked):
        """uploads changes made to local vuln database to the git repository."""

        # first pull the repo -->
        # if changed --> warning + window
        refresh_button = self.layout().itemAt(0).widget().widget(0).widget.layout().itemAt(3).widget()
        if self.git.git_update() or refresh_button.styleSheet() == "QPushButton { background-color : red }":
            self.refresh_tab_widget()
            WarningWindow = QMessageBox()
            WarningWindow.setText("Please retry, the file just has been updated and\nthe window refresh")
            WarningWindow.exec()
            return

        # else write the file
        for ident in checked:
            if self.style[ident] == GREEN: # if the style is green, it's mean that the vuln is present in the git db and not in the local db
                del self.json_db_git[ident]
            else:
                self.json_db_git[ident] = self.json_db[ident]
            jsondb = "{\"_default\":" + \
                json.dumps({int(x): self.json_db_git[x]
                            for x in self.json_db_git.keys()}, sort_keys=True) + "}"
            with open(DB_VULNS_GIT, 'w') as output:
                output.write(jsondb)
            with open(DB_VULNS_GIT_UPDATED, 'w') as output:
                output.write(jsondb)

            # and commit and push --> self.git.git_upload()
            self.git.git_upload()

        # To also update repator window
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
        self.refresh_repator(repator)
        self.update_diffs()
        self.refresh_tab_widget()

    def upload_one_change(self):
        """uploads changes made to local vuln database to the git repository. of one vuln"""
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window

        refresh_button = self.layout().itemAt(0).widget().widget(0).widget.layout().itemAt(3).widget()
        git_label = repator.layout().itemAt(5).widget()
        if self.git.git_update() or refresh_button.styleSheet() == "QPushButton { background-color : red }":
            self.refresh_tab_widget()
            WarningWindow = QMessageBox()
            WarningWindow.setText("Please retry, the file just has been updated and\nthe window refresh")
            WarningWindow.exec()
            return
        if git_label.styleSheet() == "QPushButton { background-color : red }":
            WarningWindow = QMessageBox()
            WarningWindow.setText("Could not copnnect to the git repo\nPlease check your Internet connection or the connection to the repo.")
            WarningWindow.exec()
            return

        index = self.tabw.currentIndex()
        ident = self.tabw.tabText(index)
        if self.style[ident] == GREEN: # if the style is green, it's mean that the vuln is present in the git db and not in the local db
            del self.json_db_git[ident]
        else:
            self.json_db_git[ident] = self.json_db[ident]
        jsondb = "{\"_default\":" + \
            json.dumps({int(x): self.json_db_git[x]
                        for x in self.json_db_git.keys()}, sort_keys=True) + "}"
        with open(DB_VULNS_GIT, 'w') as output:
            output.write(jsondb)
        with open(DB_VULNS_GIT_UPDATED, 'w') as output:
            output.write(jsondb)

        self.git.git_upload()

        # To also update repator window
        self.refresh_repator(repator)
        self.update_diffs()
        self.refresh_tab_widget()

    def hide_changes(self, checked):
        """Allows to choose which vulnerabilities are not followed."""
        self.hidden_vulns.clear()
        self.hidden_vulns.update(checked)
        self.refresh_tab_widget()

    def patch_changes(self, checked):
        """Allows to choose which changes to apply to the local vuln database."""
        for ident in checked:
            if self.style[ident] == RED:
                del self.json_db[ident]
            else:
                self.json_db[ident] = self.json_db_git[ident]
            jsondb = "{\"_default\":" + \
                json.dumps({int(x): self.json_db[x]
                            for x in self.json_db.keys()}, sort_keys=True) + "}"
            with open(DB_VULNS, 'w') as output:
                output.write(jsondb)
            # To also update repator window
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
        self.refresh_repator(repator)
        self.update_diffs()
        self.refresh_tab_widget()

    def hide_one_change(self):
        """Stops following the current vulnerability."""
        index = self.tabw.currentIndex()
        ident = self.tabw.tabText(index)
        self.hidden_vulns.add(ident)
        self.buttons["hideBtn"].checked[ident] = True
        fields = self.tabw.widget(0).fields
        for widget in fields:
            name = widget.split("-")
            if len(name) > 1:
                if name[1] == ident:
                    fields[widget].hide()
        self.close_tab(index)

    def patch_one_change(self):
        """Applies remote changes to local vuln database."""
        index = self.tabw.currentIndex()
        ident = self.tabw.tabText(index)

        if self.style[ident] == RED:
            del self.json_db[ident]
        else:
            self.json_db[ident] = self.json_db_git[ident]
        jsondb = "{\"_default\":" + \
            json.dumps({int(x): self.json_db[x]
                        for x in self.json_db.keys()}, sort_keys=True) + "}"
        with open(DB_VULNS, 'w') as output:
            output.write(jsondb)
        # To also update repator window
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
                vulns = repator.layout().itemAt(
                    0).widget().widget(3).fields["vulns"]
        # Patches the "All" tab for repator
        tab = vulns.tabw.widget(0)
        if self.style[ident] == GREEN or self.style[ident] == RED:
            self.refresh_repator(repator, [ident])
        else:
            for field in ["category", "sub_category", "name"]:
                tab.fields[field + "-" + ident].setText(
                    self.json_db[ident][field])
                self.refresh_repator(repator)
        self.update_diffs()
        self.refresh_tab_widget()

    def add_changed_entries(self, lst):
        """Adds all entries from self.style to the tab "All"."""
        entry = sorted(self.style.keys(), key=int)
        for ident in entry:
            if ident not in self.hidden_vulns:
                item = self.db_initial.search_by_id(
                    int(ident)) or self.db_git.search_by_id(int(ident))
                self.add_fct(lst, ident, item)

    def close_tab(self, index):
        """Close tab button handler."""
        del self.tabs[self.tabw.tabText(index)]
        self.tabw.removeTab(index)

    def see_changes_vuln(self, doc_id):
        """Creates the next tab with the details about the vuln."""
        vuln_initial = self.db_initial.search_by_id(int(doc_id))
        vuln_git = self.db_git.search_by_id(int(doc_id))
        style = self.style[doc_id] if doc_id in self.style else dict()

        if len(LANGUAGES) > 1:
            first_lang = True
            lst = dict()
            for lang in LANGUAGES:
                if first_lang:
                    lst[lang] = vuln_changes(
                        doc_id, vuln_initial, vuln_git, style)
                    first_lang = False
                else:
                    lst[lang] = vuln_changes(
                        doc_id, vuln_initial, vuln_git, style, lang)
            self.add_tab(str(doc_id), lst, self.db_initial)
            for tab in self.tabs[str(doc_id)]:
                self.tabs[str(doc_id)][tab].widget.layout(
                ).setVerticalSpacing(10)
                self.tabs[str(doc_id)][tab].widget.layout(
                ).setHorizontalSpacing(20)
                VulnsGit.set_global_word_wrap(self.tabs[str(doc_id)][tab])
                self.tabs[str(doc_id)][tab].update_cvss(doc_id)
                # To update histories only once all the widgets are created
                for widget in self.tabs[str(doc_id)][tab].fields:
                    if isinstance(self.tabs[str(doc_id)][tab].fields[widget], QComboBox):
                        self.update_history(
                            widget, self.tabs[str(doc_id)][tab], 0)
                self.setup_style(self.tabs[str(doc_id)][tab], str(
                    doc_id), tab if LANGUAGES.index(tab) != 0 else "")
        else:
            lst = vuln_changes(doc_id, vuln_initial, vuln_git, style)
            self.add_tab(str(doc_id), lst, self.db_initial)
            self.tabs[str(doc_id)].widget.layout().setVerticalSpacing(10)
            self.tabs[str(doc_id)].widget.layout().setHorizontalSpacing(20)
            VulnsGit.set_global_word_wrap(self.tabs[str(doc_id)])
            self.tabs[str(doc_id)].update_cvss(doc_id)
            # To update histories only once all the widgets are created
            for widget in self.tabs[str(doc_id)].fields:
                if isinstance(self.tabs[str(doc_id)].fields[widget], QComboBox):
                    self.update_history(widget, self.tabs[str(doc_id)], 0)
            self.setup_style(self.tabs[str(doc_id)], str(doc_id))

    @staticmethod
    def set_global_word_wrap(tab):
        """Goes through all QLabel widgets and sets wordWrap to True."""
        for i in range(tab.widget.layout().count()):
            widget = tab.widget.layout().itemAt(i).widget()
            if isinstance(widget, QLabel):
                widget.setWordWrap(True)

    def init_db_local_git(self):
        """Initializes self.json_db_git and self.json_db."""
        self.json_db = json.loads(
            open(DB_VULNS, 'r').read())["_default"]
        self.json_db_git = json.loads(
            open(DB_VULNS_GIT, 'r').read())["_default"]

    def update_diffs(self):
        """Diffs between json_db_git and json_db and stores it into self.style."""
        style = dict()
        for ident in self.json_db_git:
            if ident not in self.json_db:
                style[ident] = GREEN
        for ident in self.json_db:
            if ident not in self.json_db_git:
                style[ident] = RED
            else:
                if self.json_db_git[ident] != self.json_db[ident]:
                    style[ident] = BLUE
        self.style = style

    def setup_style(self, tab, doc_id, lang=""):
        """Sets the style for CVSS and HEADERS fields."""
        style = self.style[doc_id]
        VulnsGit.set_style(tab, style, "id-" + doc_id)
        VulnsGit.set_style(tab, style, "status")
        for header in [h + lang + "-" + doc_id for h in HEADERS.union(HISTORIES)]:
            if style == GREEN or (not tab.fields[header + "-1"].text() and
                                  tab.fields[header + "-2"].text()):
                VulnsGit.set_style(tab, GREEN, header + "-2")
                VulnsGit.set_style(tab, GREEN, header)
            elif style == RED or (not tab.fields[header + "-2"].text() and
                                  tab.fields[header + "-1"].text()):
                VulnsGit.set_style(tab, RED, header + "-1")
                VulnsGit.set_style(tab, RED, header)
            elif tab.fields[header + "-1"].text() != tab.fields[header + "-2"].text():
                VulnsGit.set_style(tab, BLUE, header + "-1")
                VulnsGit.set_style(tab, BLUE, header + "-2")
                VulnsGit.set_style(tab, BLUE, header)
        for header in [c + "-" + doc_id for c in CVSS]:
            if style == GREEN or (not tab.fields[header + "-1"].text() and
                                  tab.fields[header + "-2"].text()):
                VulnsGit.set_style(tab, GREEN, header + "-2")
            elif style == RED or (not tab.fields[header + "-2"].text() and
                                  tab.fields[header + "-1"].text()):
                VulnsGit.set_style(tab, RED, header + "-1")
            elif tab.fields[header + "-1"].text() != tab.fields[header + "-2"].text():
                VulnsGit.set_style(tab, BLUE, header + "-1")
                VulnsGit.set_style(tab, BLUE, header + "-2")

    @staticmethod
    def set_style(tab, color, label):
        """Sets the color of a QLabel."""
        tab.fields[label].setStyleSheet("QLabel { color : " + color + " }")

    @staticmethod
    def init_history_color(lang, tab, doc_id):
        """Initializes the colors inside the comboboxes and labels for HISTORY fields."""
        if "name" + lang + "-" + doc_id not in tab.fields:
            lang = "" # if the lang is not here it's because it is the first lang
        for history in HISTORIES:
            field_names = [ history + "History" + lang + "-" + doc_id + suffix
                            for suffix in ["", "-1", "-2" ]]
            fields = [tab.fields[name] for name in field_names]

            # comparaison du bas vers le haut
            n1 = fields[1].count()
            n2 = fields[2].count()
            diff = n1 - n2
            min_count = n1 if diff < 0 else n2
            for i in range(min_count):
                if fields[1].itemText(n1 - i) != fields[2].itemText(n2 - i):
                    fields[1].setItemData(
                        n1 - i, QColor(BLUE), Qt.ForegroundRole)
                    fields[2].setItemData(
                        n2 - i, QColor(BLUE), Qt.ForegroundRole)
                    VulnsGit.set_style(tab, BLUE, field_names[0])
            if diff > 0:
                for i in range(1, diff+1): # the first text is always the same (New /sommething/)
                    fields[1].setItemData(i, QColor(RED), Qt.ForegroundRole)
                    VulnsGit.set_style(tab, BLUE, field_names[0])
            elif diff < 0:
                for i in range(1, 1-diff): # the first text is always the same (New /sommething/)
                    fields[2].setItemData(i, QColor(GREEN), Qt.ForegroundRole)
                    VulnsGit.set_style(tab, BLUE, field_names[0])
            if not min_count and diff > 0:
                VulnsGit.set_style(tab, RED, field_names[0])
                fields[1].setItemData(0, QColor(RED), Qt.ForegroundRole)
            if not min_count and diff < 0:
                VulnsGit.set_style(tab, GREEN, field_names[0])
                fields[2].setItemData(0, QColor(GREEN), Qt.ForegroundRole)

    def update_history(self, field_name, tab, index):
        """Changes the text and colors in the QLabels below history comboboxes."""
        # To make sure all the widgets are already set
        if len(tab.fields) == 99:
            field_name_list = field_name.split("-")
            doc_id = field_name_list[-2]
            acc = None
            for lang in LANGUAGES:
                if '-'.join(field_name_list[:-2])[-len(lang):] == lang:
                    acc = lang
            field_label_name = field_name.replace("History", "")
            vuln_initial = self.db_initial.search_by_id(int(doc_id))
            vuln_git = self.db_git.search_by_id(int(doc_id))
            data = ""
            if vuln_initial and field_name[-1] == '1':
                basic_field = ('-'.join(field_name_list[:-2])
                               if '-'.join(field_name_list[:-2]) in vuln_initial
                               else '-'.join(field_name_list[:-2])[:-len(acc)])
                if vuln_initial[basic_field]:
                    data = vuln_initial[basic_field][index]
            elif vuln_git and field_name[-1] == '2':
                basic_field = ('-'.join(field_name_list[:-2])
                               if '-'.join(field_name_list[:-2]) in vuln_git
                               else '-'.join(field_name_list[:-2])[:-len(acc)])
                if vuln_git[basic_field]:
                    data = vuln_git[basic_field][index]
            try:
                color = tab.fields[field_name].itemData(
                    index, Qt.ForegroundRole).name()
            except AttributeError:
                color = DEFAULT
            VulnsGit.set_style(tab, color, field_label_name)
            tab.fields[field_label_name].setText(data)

    def update_cvss_metrics(self, doc_id, tab):
        """Gets the appropriate CVSS scores and sets colors accordingly."""
        color0 = 3
        color1 = 3
        color2 = 3
        scores = {"CVSS", "CVSSimp", "CVSSexp"}
        risks = {"riskLvl", "impLvl", "expLvl"}

        fields = tab.fields

        for j in range(1, 3):
            attack_vector = fields["AV-" + str(doc_id) + "-" + str(j)].text()
            attack_complexity = fields["AC-" +
                                       str(doc_id) + "-" + str(j)].text()
            privileges_required = fields["PR-" +
                                         str(doc_id) + "-" + str(j)].text()
            user_interaction = fields["UI-" +
                                      str(doc_id) + "-" + str(j)].text()
            scope = fields["S-" + str(doc_id) + "-" + str(j)].text()
            confidentiality = fields["C-" + str(doc_id) + "-" + str(j)].text()
            integrity = fields["I-" + str(doc_id) + "-" + str(j)].text()
            availability = fields["A-" + str(doc_id) + "-" + str(j)].text()
            if (attack_vector and attack_complexity and privileges_required and
                    user_interaction and scope and confidentiality and
                    integrity and availability):
                cvss, imp, exp = cvssv3(attack_vector, attack_complexity,
                                        privileges_required, user_interaction,
                                        scope, confidentiality, integrity,
                                        availability)
                r_lvl, i_lvl, e_lvl = risk_level(attack_vector,
                                                 attack_complexity,
                                                 privileges_required,
                                                 user_interaction, scope,
                                                 confidentiality, integrity,
                                                 availability)
                fields["CVSS-" + str(doc_id) + "-" + str(j)].setText(str(cvss))
                fields["CVSSimp-" + str(doc_id) + "-" +
                       str(j)].setText(str(imp))
                fields["CVSSexp-" + str(doc_id) + "-" +
                       str(j)].setText(str(exp))
                fields["riskLvl-" + str(doc_id) + "-" + str(j)].setText(r_lvl)
                fields["impLvl-" + str(doc_id) + "-" + str(j)].setText(i_lvl)
                fields["expLvl-" + str(doc_id) + "-" + str(j)].setText(e_lvl)

        if self.style[doc_id] == RED:
            color0 = 2
            color1 = 2
            color2 = 2
        elif self.style[doc_id] == GREEN:
            color0 = 1
            color1 = 1
            color2 = 1
        else:
            for widget in fields:
                for cvss in CVSS:
                    if widget == cvss + "-" + doc_id + "-1":
                        if (widget in self.style[doc_id] and
                                not widget[:-1] + "2" in self.style[doc_id]):
                            color0 &= 2
                        elif (not widget in self.style[doc_id] and
                              widget[:-1] + "2" in self.style[doc_id]):
                            color0 &= 1
                        elif fields[widget].text() != fields[widget[:-1] + "2"].text():
                            color0 &= 0
                for score in scores:
                    if widget == score + "-" + doc_id + "-1":
                        if not fields[widget[:-1] + "2"].text():
                            self.set_style(tab, RED, widget)
                            color1 &= 2
                        elif not fields[widget].text():
                            self.set_style(tab, GREEN, widget)
                            color1 &= 1
                        elif fields[widget].text() != fields[widget[:-1] + "2"].text():
                            self.set_style(tab, BLUE, widget)
                            self.set_style(tab, BLUE, widget[:-1] + "2")
                            color1 &= 0
                for risk in risks:
                    if widget == risk + "-" + doc_id + "-1":
                        if not fields[widget[:-1] + "2"].text():
                            self.set_style(tab, RED, widget)
                            color2 &= 2
                        elif not fields[widget].text():
                            self.set_style(tab, GREEN, widget)
                            color2 &= 1
                        elif fields[widget].text() != fields[widget[:-1] + "2"].text():
                            self.set_style(tab, BLUE, widget)
                            self.set_style(tab, BLUE, widget[:-1] + "2")
                            color2 &= 0
        self.set_style(tab, COLORS[color0], "CVSSLabel")
        self.set_style(tab, COLORS[color1], "CVSSScoreLabel")
        self.set_style(tab, COLORS[color2], "CVSSRiskLabel")

    def update_status(self):
        """Update the icon next to the vuln ID."""
        entry = sorted(self.style.keys())
        for ident in entry:
            fields = self.tabs["All"].fields
            if ident not in self.hidden_vulns:
                color = self.style[ident]
                if color == BLUE:
                    fields["diff-" + str(ident)].edited()
                if color == RED:
                    fields["diff-" + str(ident)].deleted()
                if color == GREEN:
                    fields["diff-" + str(ident)].added()

    def refresh_tab_widget(self):
        """Rebuilds the widget with the tabs currently open."""
        tabs = []
        for i in range(self.tabw.tabBar().count() - 1, 0, -1):
            tabs.append(self.tabw.tabBar().tabText(i))
            self.tabw.tabBar().removeTab(i)
        self.lst = copy(VULNS_INITIAL)
        self.init_tab()
        self.grid.replaceWidget(self.layout().itemAt(0).widget(), self.tabw)
        for doc_id in reversed(tabs):
            if doc_id in self.style:
                self.see_changes_vuln(doc_id)
        self.tabw.setCurrentWidget(self.tabs["All"])
        self.grid.itemAt(0).widget().currentChanged.connect(
            self.change_bottom_buttons)

    def refresh_repator(self, repator, index=None):
        """Rebuilds the vulns widget repator with the tabs currently open (without index)"""
        vulns = repator.layout().itemAt(0).widget().widget(3).fields["vulns"]
        tabs = []
        for i in range(vulns.tabw.tabBar().count() - 1, 0, -1):
            tabs.append(vulns.tabw.tabBar().tabText(i))
            self.tabw.tabBar().removeTab(i)
        if index:
            for i in index:
                if i in tabs:
                    tabs.remove(i)

        del vulns.database
        vulns.tabw.deleteLater()
        vulns.lst = copy(VULNS)
        vulns.database = DBHandler.vulns()
        vulns.tabs = {}
        vulns.init_tab()
        vulns.grid.replaceWidget(vulns.layout().itemAt(0).widget(), vulns.tabw)

        for doc_id in reversed(tabs):
            vulns.tabs["All"].fields["edit-" + doc_id].animateClick()
        vulns.tabw.setCurrentWidget(vulns.tabs["All"])

    def toggle_hide(self):
        """Toggles self.hide."""
        self.hide = False and self.hide

    def git_refresh(self):
        """Reloads self.json_db_git after updating git."""
        self.git.refresh()
        self.json_db_git = json.loads(
            open(DB_VULNS_GIT, 'r').read())["_default"]
