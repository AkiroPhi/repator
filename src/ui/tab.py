"""Module that generates the different tab types"""

# coding=utf-8
import os
from collections import OrderedDict, defaultdict
from re import sub

from PyQt5.QtCore import Qt, QDate, pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QScrollArea, QGridLayout, QWidget, QLabel, QLineEdit, QDateEdit, QDialog

from conf.report import LANGUAGES
from conf.ui_auditors import add_people
from conf.ui_vuln_edit import vuln_editing
from conf.ui_vulns import add_vuln
from src.status_vuln import status_vuln
from src.cvss import cvssv3, risk_level
from src.dbhandler import DBHandler
from src.ui.diff_status import DiffStatus
from src.ui.sort_button import SortButton
from src.ui.history import History


class Tab(QScrollArea):
    """Class that contains the attributes of a tab for repator, diffs and repator->Vulns."""

    # Whenever a tab field is modified, transmits an 'updateField' signal
    updateField = pyqtSignal(QScrollArea, bool, name="updateField")

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
        self.lst_images = defaultdict(lambda: list())
        self.lst_loaded = {}

        self.init_tab()
        self.init_buttons_status()
        self.initialized = True

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
        self.updateField.emit(self, True)

    def update_vuln(self, string=None):
        """Updates the database value of the sender and updates the fields values accordingly."""
        tab_Vulns = self.get_parent(self.sender()).tabs["Vulns"]
        tab_Vulns.updateField.emit(tab_Vulns, True)

        # If the tab is not completely initialized, we do not update since the values are already up to date
        if hasattr(self, 'initialized'):
            # Gets first parent with accessible name (the modified field)
            sender = self.get_parent(self.sender(), firstAccessibleName=True)
            if sender is None:
                return
            field_name = sender.accessibleName()
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

        # Gets the 'vulns' tab from the object that sent the signal (the modified 'Script' field)
        # Gets the vulnerability id that called the method
        sender = self.get_parent(self.sender(), "vulns")
        doc_id = self.get_parent(self.sender(), firstAccessibleName=True).accessibleName().split('-')[1]
        if sender is None or doc_id is None:
            return

        sender.tabs["All"].fields["buttonScript-" + doc_id].setEnabled(len(string) > 0)
        self.updateField.emit(self, True)

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

    def save_history_image(self, history_field_name):
        """Updates the images history."""

        # Gets the 'vulns' tab
        tab_vuln = self.get_parent(self.parent(), "vulns")
        if tab_vuln is None:
            return

        tab_all = tab_vuln.tabs["All"]
        field_tab = history_field_name.split('-')

        # Gets the fields containing the history of images texts and update it if necessary
        images_text = tab_all.lst[field_tab[0] + "Text-" + field_tab[1]]["value"]
        images_history = tab_all.lst[field_tab[0] + "History-" + field_tab[1]]["value"]
        for index in range(len(images_text)):
            if images_text[index] not in images_history:
                images_history.append(images_text[index])

    def save_histories(self):
        """Writes all histories into the database."""
        for name in self.fields:
            if name.find("History-") > 0:
                self.save_history(name)
            if "images-" in name:
                self.save_history_image(name)

    def update_history(self, index):
        """Calls the parent function that updates the History field."""
        self._parent.update_history(self.sender().accessibleName(),
                                    self, index)
        self.updateField.emit(self, True)

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
        self.updateField.emit(self, True)

    def load(self, values):
        """Loads values into the database and displays it on the screen."""
        if "vulns" in self.fields:
            self.fields["vulns"].load(values)
            return

        # Creates a .json containing auditors and clients
        # Updates currents auditors and clients
        if self.database is not None and "db" in values:
            db_path = self.database.path
            default_values = self.database.default_values
            os.remove(db_path)
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

                # Adds value that are not currently present
                if self.add_fct is not None and \
                        (name not in self.lst_loaded and self.database.search_by_id(int(doc_id)) is None)\
                        or (name in self.lst_loaded and self.database.search_by_id(int(self.lst_loaded[name])) is None):
                    doc_id = self.database.insert_record(value)

                    lst = OrderedDict()
                    self.add_fct(lst, doc_id, self.database.search_by_id(doc_id))
                    self.parse_lst(lst)
                    for ident, field in lst.items():
                        self.lst[ident] = field
                    self.fields["buttonScript-" + str(doc_id)].setEnabled(len(value["script"]) > 0)
                    self.fields["categorySort"].connect_buttons(doc_id)
                    self.fields["diff-" + str(doc_id)].added()
                    doc_id = str(doc_id)

                # Updates value that are currently present
                elif name in self.lst_loaded or self.database.search_by_id(int(doc_id)) is not None:
                    if name in self.lst_loaded:
                        doc_id = self.lst_loaded[name]
                    vuln = self.database.search_by_id(int(doc_id))
                    is_updated = False

                    # Updates the fields corresponding to the value
                    for keys in value:
                        if keys in vuln and vuln[keys] != value[keys]:
                            is_updated = True
                            self.database.update(int(name), keys, value[keys])

                    # If a field has been updated, the icon and button script is also updated
                    if is_updated:
                        self.fields["buttonScript-" + str(doc_id)].setEnabled(len(value["script"]) > 0)
                        self.fields["categorySort"].connect_buttons(doc_id)
                        self.fields["diff-" + str(doc_id)].edited()

                if "check-" + doc_id in self.fields:
                    self.fields["check-" + doc_id].setCheckState(Qt.Checked)
                if "status" in value and "isVuln-" + doc_id in self.fields:
                    self.fields["isVuln-" +
                                doc_id].setCurrentText(value["status"])
                for name_field in value.keys():

                    # Change the text of each field found in the tab
                    if name_field + "-" + doc_id in self.fields and \
                            not isinstance(self.fields[name_field + "-" + doc_id], dict):
                        self.fields[name_field + "-" + doc_id].setText(value[name_field])

                self.lst_loaded[name] = doc_id

            elif name in self.fields:
                field = self.fields[name]
                if "setText" in dir(field):
                    field.setText(value)
                if "setCurrentText" in dir(field):
                    field.setCurrentText(value)
                if "setDate" in dir(field):
                    field.setDate(QDate.fromString(value))

        for ident, value in self.fields.items():
            if isinstance(value, SortButton):
                value.update_values()
        self.updateField.emit(self, True)

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
        self.updateField.emit(self, False)
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
        doc_id = self.sender().accessibleName().split("-")[1]
        sender = self.get_parent(self.sender(), "vulns")
        if sender is None:
            return

        diff = self.fields["diff-" + doc_id]
        if diff.status() != DiffStatus.DELETED and diff.status() != DiffStatus.ADDED:
            diff.deleted()
            return

        if doc_id in sender.tabs:
            sender.close_tab(list(sender.tabs).index(doc_id))

        name_lst = list()

        for name in self.fields:
            split = name.split("-")
            if len(split) > 1:
                if name.split("-")[1] == doc_id:
                    name_lst.append(name)

        for name in name_lst:
            if not isinstance(self.fields[name], dict):
                self.grid.removeWidget(self.fields[name])
                self.fields[name].deleteLater()
            del self.fields[name]
            del self.lst[name]

        if doc_id in self.values:
            del self.values[doc_id]
        self.database.delete(int(doc_id))
        self.fields["categorySort"].update_values()
        tab_Vulns = self.get_parent(self).tabs["Vulns"]
        tab_Vulns.updateField.emit(tab_Vulns, True)

    def add_vuln(self):
        """Adds a vuln to the database and displays it as a newly added vuln."""
        doc_id = self.database.insert_record()
        lst = OrderedDict()
        add_vuln(lst, doc_id, self.database.search_by_id(doc_id))
        self.parse_lst(lst)
        for ident, field in lst.items():
            self.lst[ident] = field
        self.fields["buttonScript-" + str(doc_id)].setEnabled(False)
        self.fields["categorySort"].connect_buttons(doc_id)
        self.fields["diff-" + str(doc_id)].added()
        tab_Vulns = self.get_parent(self).tabs["Vulns"]
        tab_Vulns.updateField.emit(tab_Vulns, True)

    def status_vuln(self):
        """Calculates the status of the selected vulnerability.
        This method is called by a signal"""

        # Gets the selected vulnerability ID
        sender = self.get_parent(self.sender(), firstAccessibleName=True)
        if sender is None:
            return

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
        self.updateField.emit(self, True)

    def add_image(self, index, name):
        """Adds image to the internal storage of the 'all' tab."""

        # Gets the 'All' tab inside 'vulns' tab
        tab_all = self.get_parent(self.parent(), "vulns").tabs["All"]
        if tab_all is None:
            return

        field_tab = self.sender().accessibleName().split('-')
        self.lst_images[field_tab[1]] += [index]

        path_name_lst = field_tab[0] + "Path-" + field_tab[1]
        text_name_lst = field_tab[0] + "Text-" + field_tab[1]
        for lang in LANGUAGES:
            if lang in field_tab[0]:
                path_name_lst = path_name_lst.replace(lang, "")
                text_name_lst = text_name_lst.replace(lang, "")
        tab_all.lst[path_name_lst]["value"] += [name]
        tab_all.lst[text_name_lst]["value"] += [""]
        self.updateField.emit(self, True)

    def remove_image(self, index):
        """Removes the index image of the internal storage of the 'all' tab."""

        # Gets the 'All' tab inside 'vulns' tab
        tab_all = self.get_parent(self.parent(), "vulns").tabs["All"]
        if tab_all is None:
            return

        field_tab = self.sender().accessibleName().split('-')
        index_images = list(self.lst_images[field_tab[1]]).index(index)
        del self.lst_images[field_tab[1]][index_images]

        path_name_lst = field_tab[0] + "Path-" + field_tab[1]
        text_name_lst = field_tab[0] + "Text-" + field_tab[1]
        for lang in LANGUAGES:
            if lang in field_tab[0]:
                path_name_lst = path_name_lst.replace(lang, "")
                text_name_lst = text_name_lst.replace(lang, "")
        del tab_all.lst[path_name_lst]["value"][index_images]
        del tab_all.lst[text_name_lst]["value"][index_images]
        self.updateField.emit(self, True)

    def modify_image(self, index, name, string):
        """Modifies the index image of the internal storage of the 'all' tab."""

        # Gets the 'All' tab inside 'vulns' tab
        tab_all = self.get_parent(self.parent(), "vulns").tabs["All"]
        if tab_all is None:
            return

        field_tab = self.sender().accessibleName().split('-')
        index_images = list(self.lst_images[field_tab[1]]).index(index)

        path_name_lst = field_tab[0] + "Path-" + field_tab[1]
        text_name_lst = field_tab[0] + "Text-" + field_tab[1]
        for lang in LANGUAGES:
            if lang in field_tab[0]:
                path_name_lst = path_name_lst.replace(lang, "")
                text_name_lst = text_name_lst.replace(lang, "")
        tab_all.lst[path_name_lst]["value"][index_images] = name
        tab_all.lst[text_name_lst]["value"][index_images] = string
        self.updateField.emit(self, True)

    def get_parent(self, parent, name=None, firstAccessibleName=False):
        """Internal method returning the parent with accessible name 'name'.
        If 'firstName' is True, returns the first parent.
        If 'name' is None, returns the highest parent."""
        sender = parent
        while True:
            field_name = sender.accessibleName()
            if (firstAccessibleName and field_name) or (name is not None and name in field_name):
                return sender
            if sender.parent() is None:
                return None if name is not None else sender
            sender = sender.parent()

    def set_status_vuln(self, doc_id, dispay_popup_error=False):
        """Internal method replacing the variables from the script corresponding with the ID"""

        vuln = self.database.search_by_id(int(doc_id))
        if "script" in vuln and len(vuln["script"]) > 0:
            # Gets the Window tab
            tab_window = self.get_parent(self.sender())
            if tab_window is None:
                return

            fields = tab_window.tabs["Mission"].fields
            script = vuln["script"]

            # Replace all variables
            for ident, field in fields.items():
                if isinstance(field, QLineEdit) or isinstance(field, QDateEdit):
                    for var_field in {ident, ident.lower(), ident.upper(), ident.capitalize()}:
                        script = script.replace("##" + var_field + "##", field.text())

            # Calculate the status and display a popup if necessary
            result = status_vuln(script, (vuln["regexVuln"], vuln["regexNotVuln"]))
            if result is not None and result[0] in self.valid_status_vuln \
                    and "isVuln-" + doc_id in self.fields:
                self.fields["isVuln-" +
                            doc_id].setCurrentText(result[0])
            elif dispay_popup_error and (result is None or not result[0] in self.valid_status_vuln):
                self.display_error_test(result)
        self.updateField.emit(self, True)

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

        message = ""
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
        The size of the popup can be chosen or calculated."""

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
                self.updateField.emit(self, True)
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

            # If "class" is not in field, then it's only a field for storing data do it's not displayed
            if "class" in field:
                if "args" in field:
                    widget = field["class"](*(field["args"] + [self]))
                elif "arg" in field:
                    widget = field["class"](field["arg"], self)
                    try:
                        getattr(widget, field["class"]).emit(field["arg"])
                    except (TypeError, AttributeError):
                        pass
                else:
                    widget = field["class"](self)

                    # if it's the identifier 'image', we recover the fields in the 'All' tab of 'vulns' tab
                    #   the information of the images that are currently saved
                    if "images" in ident:

                        # We go up the parents until we find the Vulns tab, retrieving the images memory
                        tab_all = self.get_parent(self.sender(), "vulns").tabs["All"]
                        if tab_all is None:
                            return

                        doc_id = ident.split("-")[1]
                        if "imagesPath-" + doc_id in tab_all.lst:
                            paths = tab_all.lst["imagesPath-" + doc_id]["value"]
                            texts = tab_all.lst["imagesText-" + doc_id]["value"]
                            history = tab_all.lst["imagesHistory-" + doc_id]["value"]
                            for index in range(len(texts)):
                                self.lst_images[doc_id] += [index]
                                widget.add_chooser(
                                    paths[index], texts[index], history)
                            widget.set_history(history)
                            widget.add_chooser()

                widget.setAccessibleName(ident)
                self.fields[ident] = widget

                if "signal" in field:

                    # If there are several signals, we associate each signal with the
                    #   corresponding function (with same index)
                    if isinstance(field["signal"], list):
                        for index in range(len(field["signal"])):
                            if "signalFct" in field:
                                self.set_signal(widget, field["signal"][index], field["signalFct"][index])
                            else:
                                getattr(widget, field["signal"][index]).connect(self.change_value)
                    else:
                        if "signalFct" in field:
                            if isinstance(field["signalFct"], list):
                                for signal in field["signalFct"]:
                                    self.set_signal(widget, field["signal"], signal)
                            else:
                                self.set_signal(widget, field["signal"], field["signalFct"])
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

                if "setDate" in field:
                    widget.setDate(field["setDate"])

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

                    # Adds a symbol (or image if it's available) to warn the user that help is available
                    if "help" in field:
                        label = ClickableQWidget()
                        layout = QGridLayout(label)
                        layout.setContentsMargins(0, 0, 0, 0)
                        if "helpLogo" in field and len(field["helpLogo"]) > 0:
                            pixmap = QPixmap(field["helpLogo"])
                            if "helpDimension" in field:
                                pixmap = pixmap.scaledToWidth(field["helpDimension"][0])
                                pixmap = pixmap.scaledToHeight(field["helpDimension"][1])

                            if not pixmap.isNull():
                                text_label = QLabel(field["label"])
                                image_label = QLabel()

                                image_label.setPixmap(pixmap)
                                image_label.setAlignment(Qt.AlignCenter)
                                text_label.setMinimumHeight(pixmap.height())
                                text_label.setAlignment(Qt.AlignCenter)

                                layout.addWidget(text_label, 0, 0, alignment=Qt.AlignLeft)
                                layout.addWidget(image_label, 0, 1, alignment=Qt.AlignLeft)
                                layout.setSpacing(0)
                                label.setLayout(layout)
                            else:
                                text_label = QLabel(field["label"] + " (?)")
                                layout.addWidget(text_label, 0, 0, alignment=Qt.AlignLeft)
                        else:
                            text_label = QLabel(field["label"] + " (?)")
                            layout.addWidget(text_label, 0, 0, alignment=Qt.AlignLeft)
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
            else:
                self.fields[ident] = field

    def set_signal(self, widget, signal, signal_fct):
        getattr(widget, signal).connect(getattr(self, signal_fct))


class ClickableQWidget(QWidget):
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
        self.setLayout(self.grid)

        self.grid.addWidget(QLabel(self.name, self))
