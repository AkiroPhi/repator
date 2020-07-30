"""Defines the UI for the window "Diffs"."""

# coding=utf-8

import collections

from PyQt5.QtWidgets import QPushButton, QLabel, QLineEdit

from src.ui.diff_status import DiffStatus
from src.ui.sort_button import SortButton

AUDITORS_INITIAL = collections.OrderedDict()
AUDITORS_INITIAL["id0"] = {"class": QLabel,
                        "arg": "ID",
                        "col": 0,
                        "colspan": 2}
AUDITORS_INITIAL["nameLabel"] = {"class": QLabel,
                              "arg": "Name",
                              "col": 2}
AUDITORS_INITIAL["phoneLabel"] = {"class": QLabel,
                                     "arg": "Phone number",
                                     "col": 3}
AUDITORS_INITIAL["emailLabel"] = {"class": QLabel,
                             "arg": "Email",
                             "col": 4}
AUDITORS_INITIAL["rolesLabel"] = {"class": QLabel,
                             "arg": "Role",
                             "col": 5}


def add_auditor_initial(lst, doc_id, auditor):
    """Function to add a member with this UI."""
    lst["id-" + str(doc_id)] = {"class": QLabel,
                                "arg": str(doc_id),
                                "setLength": 3,
                                "col": 0}
    lst["diff-" + str(doc_id)] = {"class": DiffStatus,
                                  "setLength": 3,
                                  "col": 1}
    lst["full_name-" + str(doc_id)] = {"class": QLineEdit,
                                      "arg": auditor["full_name"],
                                      "setReadOnly": True,
                                      "col": 2}
    lst["phone-" + str(doc_id)] = {"class": QLineEdit,
                                          "arg": auditor["phone"],
                                          "setReadOnly": True,
                                          "col": 3}
    lst["email-" + str(doc_id)] = {"class": QLineEdit,
                                  "arg": auditor["email"],
                                  "setReadOnly": True,
                                  "col": 4}
    lst["role-" + str(doc_id)] = {"class": QLineEdit,
                                  "arg": auditor["role"],
                                  "setReadOnly": True,
                                  "col": 5}
    lst["changes-" + str(doc_id)] = {"class": QPushButton,
                                     "clicked": "see_changes_auditor",
                                     "arg": "View changes",
                                     "setLength": 15,
                                     "col": 6}
