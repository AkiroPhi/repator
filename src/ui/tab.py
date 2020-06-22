"""Module that generates the different tab types"""

# coding=utf-8
from collections import OrderedDict
from re import sub

from PyQt5.QtCore import QDateTime, Qt, QDate, pyqtSignal
from PyQt5.QtWidgets import QScrollArea, QGridLayout, QWidget, QLabel, QLineEdit, QDateEdit, QDialog

from conf.report import LANGUAGES
from conf.ui_auditors import add_people
from conf.ui_vuln_edit import vuln_editing
from conf.ui_vulns import add_vuln
from src.status_vuln import status_vuln
from src.cvss import cvssv3, risk_level
from src.dbhandler import DBHandler
from src.ui.diff_status import DiffStatus


class Tab(QScrollArea):
    """Class that contains the attributes of a tab for repator, diffs and repator->Vulns."""

    def __init__(self, parent, lst, database=None, add_fct=None):
        super().__init__(parent)
        self.head_lst = lst
        self.database = database
        self.add_fct = add_fct
        self._parent = parent
        self.row = 0
        self.lst = self.head_lst
        self.values = OrderedDict()
        self.valid_status_vuln = ["Vulnerable", "Not Vulnerable"]

        self.init_tab()
        self.init_buttons_status()

    def init_tab(self):
        """Initializes features and widgets of a tab."""
        self.fields = {}
        if self.database is not None and self.add_fct is not None:
            items = self.database.get_all()
            for item in items:
                self.add_fct(self.lst, item.doc_id, item)

        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(5, 5, 5, 5)
        self.grid.setAlignment(Qt.AlignTop)

        self.parse_lst()

        self.widget = QWidget()
        self.widget.setLayout(self.grid)
        self.setWidget(self.widget)
        self.setWidgetResizable(True)

    def init_buttons_status(self):
        """Initializes the buttons that must be blocked (contain 'buttonScript')"""
        for ident in self.fields:
            if "buttonScript" in ident:
                doc = self.database.search_by_id(int(ident.split("-")[1]))
                self.fields[ident].setEnabled(len(doc["script"]) > 0)

    def change_value(self, string=None):
        """Changes the value of a field with the provided encoding."""
        sender = self.sender()
        field = sender.accessibleName()

        if string is None:
            string = sender
        if "toString" in dir(string):
            string = string.toString()
        if "toHtml" in dir(string):
            string = string.toHtml()

        self.values[field] = string

    def update_vuln(self, string=None):
        """Updates the database value of the sender and updates the fields values accordingly."""
        sender = self.sender()
        while True:
            field_name = sender.accessibleName()
            if field_name:
                break
            if sender.parent() is None:
                return
            sender = sender.parent()

        field_tab = field_name.split('-')

        if string is None:
            string = sender
        if "toString" in dir(string):
            string = string.toString()
        if "to_plain_text" in dir(string):
            string = string.to_plain_text()
        history_field_name = field_tab[0] + "History-" + field_tab[1]

        doc = self.database.search_by_id(int(field_tab[1]))

        diff_name = "diff-" + field_tab[1]
        if diff_name in self._parent.tabs["All"].fields:
            self._parent.tabs["All"].fields[diff_name].edited()

        if history_field_name in self.fields:
            index = self.fields[history_field_name].currentIndex()
            if index == -1 or self.fields[field_name].to_plain_text() != doc[field_tab[0] + "History"][index]:
                self.fields[history_field_name].setCurrentIndex(0)
        self.database.update(int(field_tab[1]), field_tab[0], string)
        self.update_cvss(field_tab[1])

    def update_button(self, string=None):
        """"Updates the button corresponding to the 'Script' field of the modified vulnerability.
        If the 'Script' field is empty, the button is disabled. Otherwise it's activated"""

        # Get the object that sent the signal (the modified 'Script' field)
        sender = self.sender()
        doc_id = ""

        # We go up the parents until we find the Vulns tab, retrieving the modified vulnerability ID
        while True:
            field_name = sender.accessibleName()
            if "vulns" in field_name:
                break
            if field_name:
                doc_id = field_name.split('-')[1]
            if sender.parent() is None:
                return
            sender = sender.parent()
        sender.tabs["All"].fields["buttonScript-" + doc_id].setEnabled(len(string) > 0)

    def load_history(self, index):
        """Writes the string into the non-History field of the sender."""
        sender = self.sender()
        history_field_name = sender.accessibleName()
        doc = self.database.search_by_id(
            int(history_field_name.split('-')[-1]))
        field = sub(r'History.*', 'History', history_field_name)
        if sender.currentIndex() != 0:
            field_name = history_field_name.replace("History", "")

            if field_name in self.fields:
                self.fields[field_name].set_plain_text(doc[field][index])

    def save_history(self, history_field_name):
        """Writes the history into the database."""
        if self.fields[history_field_name].currentIndex() == 0:
            field_tab = history_field_name.split('-')
            field_name = history_field_name.replace("History", "")

            value = self.fields[field_name].to_plain_text()

            history = self.database.search_by_id(
                int(field_tab[1]))[field_tab[0]]

            if value not in history:
                history.append(value)
            self.database.update(int(field_tab[1]), field_tab[0], history)

    def save_histories(self):
        """Writes all histories into the database."""
        for name in self.fields:
            if name.find("History-") > 0:
                self.save_history(name)

    def update_history(self, index):
        """Calls the parent function that updates the History field."""
        self._parent.update_history(self.sender().accessibleName(),
                                    self, index)

    def update_cvss(self, doc_id):
        """Computes the CVSS scores from the field values and writes it into the corresponding
        fields.
        """
        if "CVSS-" + str(doc_id) in self.fields:
            attack_vector = self.fields["AV-" + str(doc_id)].currentText()
            attack_complexity = self.fields["AC-" + str(doc_id)].currentText()
            privileges_required = self.fields["PR-" +
                                              str(doc_id)].currentText()
            user_interaction = self.fields["UI-" + str(doc_id)].currentText()
            scope = self.fields["S-" + str(doc_id)].currentText()
            confidentiality = self.fields["C-" + str(doc_id)].currentText()
            integrity = self.fields["I-" + str(doc_id)].currentText()
            availability = self.fields["A-" + str(doc_id)].currentText()

            cvss_values = list(cvssv3(attack_vector, attack_complexity,
                                      privileges_required, user_interaction,
                                      scope, confidentiality, integrity, availability))
            risk_level_values = list(risk_level(attack_vector, attack_complexity,
                                                privileges_required,
                                                user_interaction, scope,
                                                confidentiality, integrity, availability))

            self.fields["CVSS-" + str(doc_id)].setText(str(cvss_values[0]))
            self.fields["CVSSimp-" + str(doc_id)].setText(str(cvss_values[1]))
            self.fields["CVSSexp-" + str(doc_id)].setText(str(cvss_values[2]))

            self.fields["riskLvl-" + str(doc_id)].setText(risk_level_values[0])
            self.fields["impLvl-" + str(doc_id)].setText(risk_level_values[1])
            self.fields["expLvl-" + str(doc_id)].setText(risk_level_values[2])

    def enable_row(self):
        """Shows the row if all conditions are matched."""
        sender = self.sender()
        doc_id = sender.accessibleName().split('-')[1]

        enable = False
        if "isSelected" in dir(sender):
            if sender.isSelected():
                enable = True

        if "isChecked" in dir(sender):
            if sender.isChecked():
                enable = True

        if "currentIndex" in dir(sender):
            if sender.currentIndex() >= 2:
                enable = True

        if enable:
            self.values[doc_id] = self.database.search_by_id(int(doc_id))
            if "currentText" in dir(sender):
                self.values[doc_id]["status"] = sender.currentText()
        else:
            if doc_id in self.values:
                del self.values[doc_id]

    def update_auditor(self, string=None):
        """Gets the value of an auditor and copies it into the database."""
        sender = self.sender()
        field_name = sender.accessibleName()

        field_tab = field_name.split('-')

        if string is None:
            string = sender
        if "toString" in dir(string):
            string = string.toString()
        if "toHtml" in dir(string):
            string = string.toHtml()

        self.database.update(int(field_tab[1]), field_tab[0], string)

    def load(self, values):
        """Loads values into the database and displays it on the screen."""
        if "vulns" in self.fields:
            self.fields["vulns"].load(values)
            return

        if self.database is not None and "db" in values:
            creation_date = QDateTime.currentDateTime().toString("yyyyMMdd-hhmmss")
            db_path = self.database.path + "-tmp-" + creation_date + ".json"
            default_values = self.database.default_values
            self.database.close()
            self.database = DBHandler(db_path, default_values)
            self.database.insert_multiple(values["db"])

            if self.add_fct is not None:
                self.row = 0
                self.lst = self.head_lst
                self.values.clear()
                self.fields.clear()

                items = self.database.get_all()
                for item in items:
                    self.add_fct(self.lst, item.doc_id, item)
                self.parse_lst()

        for name, value in values.items():
            if name.isdigit():
                doc_id = name
                if "check-" + doc_id in self.fields:
                    self.fields["check-" + doc_id].setCheckState(Qt.Checked)
                if "status" in value and "isVuln-" + doc_id in self.fields:
                    self.fields["isVuln-" +
                                doc_id].setCurrentText(value["status"])

            elif name in self.fields:
                field = self.fields[name]
                if "setText" in dir(field):
                    field.setText(value)
                if "setCurrentText" in dir(field):
                    field.setCurrentText(value)
                if "setDate" in dir(field):
                    field.setDate(QDate.fromString(value))

    def save(self, database=False):
        """Saves the values of lst into self.values and takes the values from the database to save
        them into self.values.
        """
        if "list" in self.fields:
            lst = self.fields["list"]
            cpt = 0
            out_lst = {}
            while cpt < lst.count():
                item = lst.item(cpt)

                if ((item.flags() & Qt.ItemIsUserCheckable)
                        == Qt.ItemIsUserCheckable):
                    out_lst[item.text()] = item.checkState()
                else:
                    out_lst[item.text()] = True

                cpt += 1
            self.values["list"] = out_lst

        if "vulns" in self.fields:
            self.values = self.fields["vulns"].save()
            self.values = OrderedDict(
                sorted(self.fields["vulns"].save().items()))

        if database and self.database is not None:
            self.values["db"] = self.database.get_all()
        return self.values

    def edit_vuln(self):
        """Adds the tab edition for the vuln corresponding to the sender and goes to it."""
        sender = self.sender()
        doc_id = sender.accessibleName().split("-")[1]
        vuln = self.database.search_by_id(int(doc_id))
        if len(LANGUAGES) > 1:
            first_lang = True
            lst = dict()
            for lang in LANGUAGES:
                if first_lang:
                    lst[lang] = vuln_editing(doc_id, vuln)
                    first_lang = False
                else:
                    lst[lang] = vuln_editing(doc_id, vuln, lang)
        else:
            lst = vuln_editing(doc_id, vuln)
        self._parent.add_tab(str(doc_id), lst, self.database)
        if len(LANGUAGES) > 1:
            for lang in LANGUAGES:
                self._parent.tabs[str(doc_id)][lang].update_cvss(doc_id)
        else:
            self._parent.tabs[str(doc_id)].update_cvss(doc_id)

    def see_changes_vuln(self):
        """Calls the "Vulns git" function see_changes_vuln."""
        self._parent.see_changes_vuln(
            self.sender().accessibleName().split("-")[1])

    def del_vuln(self):
        """Shows a vuln as deleted on first pressure on the button "delete" and removes the vuln
        on the second pressure.
        """
        sender = self.sender()
        doc_id = sender.accessibleName().split("-")[1]

        diff = self.fields["diff-"+doc_id]
        if diff.status() != DiffStatus.DELETED and diff.status() != DiffStatus.ADDED:
            diff.deleted()
            return

        # We go up the parents until we find the Vulns tab
        while True:
            field_name = sender.accessibleName()
            if "vulns" in field_name:
                break
            if sender.parent() is None:
                return
            sender = sender.parent()

        if doc_id in sender.tabs:
            sender.close_tab(list(sender.tabs).index(doc_id))

        name_lst = list()

        for name in self.fields:
            split = name.split("-")
            if len(split) > 1:
                if name.split("-")[1] == doc_id:
                    name_lst.append(name)

        for name in name_lst:
            self.grid.removeWidget(self.fields[name])
            self.fields[name].deleteLater()
            del self.fields[name]
            del self.lst[name]

        if doc_id in self.values:
            del self.values[doc_id]
        self.database.delete(int(doc_id))
        self.fields["categorySort"].update_values()

    def add_vuln(self):
        """Adds a vuln to the database and displays it as a newly added vuln."""
        doc_id = self.database.insert_record()
        lst = OrderedDict()
        add_vuln(lst, doc_id, self.database.search_by_id(doc_id))
        self.parse_lst(lst)
        for ident, field in lst.items():
            self.lst[ident] = field
        self.fields["buttonScript-"+str(doc_id)].setEnabled(False)
        self.fields["categorySort"].connect_buttons(doc_id)
        self.fields["diff-"+str(doc_id)].added()

    def status_vuln(self):
        """Calculates the status of the selected vulnerability.
        This method is called by a signal"""
        sender = self.sender()

        # Gets the selected vulnerability ID
        while True:
            field_name = sender.accessibleName()
            if field_name:
                break
            if sender.parent() is None:
                return
            sender = sender.parent()
        self.set_status_vuln(sender.accessibleName().split("-")[1], dispay_popup_error=True)

    def status_vulns(self):
        """Calculates the status of all vulnerabilities.
        This method is called by a signal"""
        for name in self.fields:
            split = name.split("-")
            if len(split) == 2 and split[0] == "id" and len(split[1]) > 0:
                self.set_status_vuln(split[1])

    def add_auditor(self):
        """Adds an auditor to the database and displays it."""
        doc_id = self.database.insert_record()
        lst = OrderedDict()
        add_people(lst, doc_id, self.database.search_by_id(doc_id))
        self.parse_lst(lst)
        for ident, field in lst.items():
            self.lst[ident] = field

    def set_status_vuln(self, doc_id, dispay_popup_error=False):
        """Internal method replacing the variables from the script corresponding with the ID"""

        vuln = self.database.search_by_id(int(doc_id))
        if "script" in vuln and len(vuln["script"]) > 0:

            # Gets the Window tab
            sender = self.sender()
            while True:
                if sender.parent() is None:
                    break
                sender = sender.parent()
            fields = sender.tabs["Mission"].fields
            script = vuln["script"]

            # Replace all variables
            for ident, field in fields.items():
                if isinstance(field, QLineEdit) or isinstance(field, QDateEdit):
                    for var_field in {ident, ident.lower(), ident.upper(), ident.capitalize()}:
                        script = script.replace("##" + var_field + "##", field.text())

            # Calculate the status and display a popup if necessary
            result = status_vuln(script, (vuln["regexVuln"], vuln["regexNotVuln"]))
            if result is not None and result[0] in self.valid_status_vuln\
                    and "isVuln-" + doc_id in self.fields:
                self.fields["isVuln-" +
                            doc_id].setCurrentText(result[0])
            elif dispay_popup_error and (result is None or not result[0] in self.valid_status_vuln):
                self.display_error_test(result)

    def display_help_var(self):
        """Displays a popup with all availables variables"""

        # TODO: This method must be updated each time a new field is added to 'Mission' tab.
        message = "\
            For the moment, the available variables are:\n\
            \t##client##\t\t--->\tReplaced by the 'client' field\n\
            \t##target##\t\t--->\tReplaced by the 'target' field\n\
            \t##code##\t\t--->\tReplaced by the 'code' field\n\
            \t##dateStart##\t\t--->\tReplaced by the 'dateStart' field\n\
            \t##dateEnd##\t\t--->\tReplaced by the 'dateEnd' field\n\
            \t##environment##\t--->\tReplaced by the 'environment' field\n\
            \t##url##\t\t\t--->\tReplaced by the 'URL' field\n\
            \t##ip##\t\t\t--->\tReplaced by the 'IP' field\n\
            Each variable can also be matched in uppercase, lowercase and capitalized\n\
            \t(ex: dateStart, datestart, DATESTART, Datestart)"
        self.display_popup("Help", message, 0.9)

    def display_error_test(self, result):
        """Internal method displaying a popup according to the content of result"""

        if result is None:
            message = "The current script is not executable, please check the syntax !"
        elif result is not None and not result[0] in self.valid_status_vuln:
            message = "The script has been executed but no status have been determined !"
            if result[1]:
                message += "\n\tAn error message have been found during execution : \n\n{}.".format(result[2])
            else:
                message += "\n\tNo error message have been found during execution."
        self.display_popup("Warning", message, 0.9)

    def display_popup(self, title, message, opacity, x=-1, y=-1, width=-1, height=-1):
        """Displays a simple popup with message.
        The site of the popup can be chosen or calculated."""

        max_length_line = 0
        for line in message.split("\n"):
            if len(line) > max_length_line:
                max_length_line = len(line)
        popup = Popup(message, self)
        popup.setWindowTitle(title)
        popup.setWindowOpacity(opacity)
        popup.setGeometry(0 if x < 0 else x,
                          0 if y < 0 else y,
                          max_length_line * 6 if width == -1 else width,
                          (message.count("\n") + 1) * 17) if height == -1 else height
        popup.show()

    def del_auditor(self):
        """Checks for all selected auditors and remove them from the display and the database."""
        for ident, field in self.fields.items():
            selected = False
            if "isSelected" in dir(field):
                if field.isSelected():
                    selected = True

            if "isChecked" in dir(field):
                if field.isChecked():
                    selected = True

            if selected:
                for row in range(1, self.row + 1):
                    if self.grid.itemAtPosition(row, 0) is not None:
                        if self.grid.itemAtPosition(row, 0).widget().accessibleName() == ident:
                            col = 0
                            while self.grid.itemAtPosition(row, col) is not None:
                                name = self.grid.itemAtPosition(
                                    row, col).widget().accessibleName()
                                self.grid.removeWidget(self.fields[name])
                                self.fields[name].deleteLater()

                                del self.fields[name]
                                del self.lst[name]
                                col += 1

                            doc_id = ident[ident.find('-') + 1:]
                            self.database.delete(int(doc_id))

                            del self.values[doc_id]

                            self.del_auditor()

                            return

    def parse_lst(self, lst=None):
        """Parses the lst to create the objects correponding to the UI of the tab."""
        if lst is None:
            lst = self.lst

        for ident, field in lst.items():
            if "args" in field:
                widget = field["class"](*(field["args"]+[self]))
            elif "arg" in field:
                widget = field["class"](field["arg"], self)
                try:
                    getattr(widget, field["class"]).emit(field["arg"])
                except (TypeError, AttributeError):
                    pass
            else:
                widget = field["class"](self)

            widget.setAccessibleName(ident)
            self.fields[ident] = widget

            if "signal" in field:
                if "signalFct" in field:
                    if isinstance(field["signalFct"], list):
                        for signal in field["signalFct"]:
                            getattr(widget, field["signal"]).connect(
                                getattr(self, signal))
                    else:
                        getattr(widget, field["signal"]).connect(
                            getattr(self, field["signalFct"]))
                else:
                    getattr(widget, field["signal"]).connect(self.change_value)

            if "list" in field:
                for line in field["list"]["lines"]:
                    line_list = field["list"]["class"](line, widget)
                    if "flags" in field["list"]:
                        line_list.setFlags(field["list"]["flags"])
                    if "setData" in field["list"]:
                        for arg1, arg2 in field["list"]["setData"].items():
                            line_list.setData(arg1, arg2)

            if "items" in field:
                for item in field["items"]:
                    widget.addItem(item)

            if "flags" in field:
                widget.setFlags(field["flags"])

            if "setLength" in field:
                char_width = widget.fontMetrics().averageCharWidth() * 1.1
                widget.setFixedWidth(int(char_width * field["setLength"]))

            if "setData" in field:
                for arg1, arg2 in field["setData"].items():
                    widget.setData(arg1, arg2)

            if "setCurrentText" in field:
                widget.setCurrentText(field["setCurrentText"])

            if "setText" in field:
                widget.setText(field["setText"])

            if "selectionMode" in field:
                widget.setSelectionMode(field["selectionMode"])

            if "clicked" in field:
                widget.clicked.connect(getattr(self, field["clicked"]))

            if "setStyleSheet" in field:
                widget.setStyleSheet(field["setStyleSheet"])

            if "setReadOnly" in field:
                widget.setReadOnly(field["setReadOnly"])

            if "selectionMode" in field:
                widget.setSelectionMode(field["selectionMode"])

            if "label" in field:
                if "help" in field:
                    label = ClickableQLabel(field["label"] + " (?)")
                    label.clicked.connect(getattr(self, field["help"]))
                else:
                    label = QLabel(field["label"])
                self.grid.addWidget(label, self.row, 0)
                self.grid.addWidget(widget, self.row, 1, 1, -1)
            elif "col" in field:
                if field["col"] > 0:
                    self.row -= 1
                if "colspan" in field:
                    self.grid.addWidget(
                        widget, self.row + 1, field["col"], 1, field["colspan"])
                else:
                    self.grid.addWidget(widget, self.row + 1, field["col"])
            else:
                self.grid.addWidget(widget, self.row, 0, 1, 2)

            self.row += 1

class ClickableQLabel(QLabel):
    def __init(self, parent):
        super().__init__(parent)

    clicked = pyqtSignal()
    rightClicked = pyqtSignal()

    def mousePressEvent(self, ev):
        if ev.button() == Qt.RightButton:
            self.rightClicked.emit()
        else:
            self.clicked.emit()


class Popup(QDialog):
    def __init__(self, name, parent=None):
        super().__init__(parent)
        self.name = name

        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(10, 5, 10, 5)
        self.grid.setAlignment(Qt.AlignTop)

        self.grid.addWidget(QLabel(self.name, self))
        self.setLayout(self.grid)