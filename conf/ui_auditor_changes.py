"""Defines the UI for the diferrences tabs in Diffs window."""

# coding=utf-8

import collections

from PyQt5.QtWidgets import QLabel, QComboBox

from conf.report import BLUE, RED, GREEN, COLORS


def auditor_changes(doc_id: int, auditor1: dict, auditor2: dict, style: COLORS, lang: str = "") -> collections.OrderedDict :
    """
    Adds a the arguments to construct a differences tab given later to src.ui.tab.parseLst.
    """
    if style == BLUE:
        status = "Modified"
    elif style == RED:
        status = "Removed"
    elif style == GREEN:
        status = "Added"

    # To avoid the crash when editing a new auditor or a partial auditor loaded from
    # db.
    if not auditor1:
        auditor1 = dict()
    if not auditor2:
        auditor2 = dict()
    auditor1 = collections.defaultdict(lambda: "", auditor1)
    auditor2 = collections.defaultdict(lambda: "", auditor2)

    lst = collections.OrderedDict()

    lst["id-" + str(doc_id)] = {
        "class": QLabel,
        "arg": "ID  " + str(doc_id),
        "col": 0
    }
    lst["status"] = {
        "class": QLabel,
        "arg": status,
        "col": 1
    }

    lst["full_name-" + str(doc_id)] = {
        "class": QLabel,
        "arg": "Full name",
        "col": 0}
    lst["full_name-" + str(doc_id) + "-1"] = {
        "class": QLabel,
        "arg": auditor1["full_name"],
        "col": 1,
        "colspan": 4}
    lst["full_name-" + str(doc_id) + "-2"] = {
        "class": QLabel,
        "arg": auditor2["full_name"],
        "col": 5,
        "colspan": 4}

    lst["phone-" + str(doc_id)] = {
        "class": QLabel,
        "arg": "Phone",
        "col": 0}
    lst["phone-" + str(doc_id) + "-1"] = {
        "class": QLabel,
        "arg": auditor1["phone"],
        "col": 1,
        "colspan": 4}
    lst["phone-" + str(doc_id) + "-2"] = {
        "class": QLabel,
        "arg": auditor2["phone"],
        "col": 5,
        "colspan": 4}

    lst["email-" + str(doc_id)] = {
        "class": QLabel,
        "arg": "Email",
        "col": 0}
    lst["email-" + str(doc_id) + "-1"] = {
        "class": QLabel,
        "arg": auditor1["email"],
        "col": 1,
        "colspan": 4}
    lst["email-" + str(doc_id) + "-2"] = {
        "class": QLabel,
        "arg": auditor2["email"],
        "col": 5,
        "colspan": 4}

    lst["role-" + str(doc_id)] = {
        "class": QLabel,
        "arg": "Role",
        "col": 0}
    lst["role-" + str(doc_id) + "-1"] = {
        "class": QLabel,
        "arg": auditor1["role"],
        "col": 1,
        "colspan": 4}
    lst["role-" + str(doc_id) + "-2"] = {
        "class": QLabel,
        "arg": auditor2["role"],
        "col": 5,
        "colspan": 4}



    return lst
