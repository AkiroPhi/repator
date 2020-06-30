"""Defines Git class, a helper to use Git."""
# coding=utf-8
from shutil import rmtree
from git import Repo, GitCommandError
from os import mkdir

from subprocess import Popen, PIPE
from re import findall
import json
import time
from threading import Thread
from shutil import copyfile
from PyQt5.QtCore import QCoreApplication, QObject
from conf.db import DB_VULNS, DB_VULNS_GIT, DB_VULNS_GIT_UPDATED, DB_VULNS_GIT_DIR, DB_VULNS_GIT_FILE
from conf.report import SSH_KEY, GIT, REFRESH_RATE


class Git(QObject):
    """Defines interactions between repator and git."""

    def __init__(self):
        super().__init__()
        self.git_reachable = False
        self.repo = None
        self.app = QCoreApplication.instance()
        self.setParent(self.app)
        self.hidden_changes_vulns = set()
        self.background_thread = Thread(
            target=self.timer_vulnerabilities, daemon=True)
        self.background_update = Thread(
            target=self.git_update, daemon=True)
        self.git_routine()

    def init_git(self):
        """Initialises the git repository in a new directory."""
        self.clean_git()
        self.repo = Repo.init(DB_VULNS_GIT_DIR)
        ssh_cmd = "ssh -i " + SSH_KEY + " -F /dev/null"
        # self.repo.config_writer('core.sshCommand ' + ssh_cmd)
        self.repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd) # set the config ?
        self.repo.create_remote('origin', url=GIT)

    def clean_git(self):
        """Removes the git file (the thread doesn't need to be killed since it is deamonized)."""
        try:
            rmtree(DB_VULNS_GIT_DIR)
        except FileNotFoundError:
            pass

    def vulnerabilities_changed(self):
        """
        Compares DB_VULNS and DB_VULNS_GIT
        Return True if the vulnerabilities tracked changed
        """
        try:
            json_db = json.loads(
                open(DB_VULNS, 'r').read())["_default"]
            json_db_git = json.loads(
                open(DB_VULNS_GIT, 'r').read())["_default"]
        except FileNotFoundError:
            return True
        list_id = set(json_db.keys()).union(set((json_db_git.keys())))
        for ident in list_id:
            if ident not in self.hidden_changes_vulns and (ident not in json_db or ident not in json_db_git or  json_db_git[ident] != json_db[ident]):
                return True
        return False

    def git_update(self):
        """Pulls git repo and colors View changes button if the repository is unreachable. and return True if the repo has been updated."""
        repator, diffs, ret_value = None, None, False
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
            elif window.windowTitle() == "Diffs":
                diffs = window
        try:
            self.repo.remote().pull('master')
            self.git_reachable = True

            if Git.git_changed():
                copyfile(DB_VULNS_GIT_UPDATED, DB_VULNS_GIT)
                ret_value = True
                if diffs and diffs.isVisible():
                    refresh_button = diffs.layout().itemAt(0).widget().widget(0).widget.layout().itemAt(3).widget()
                    refresh_button.setStyleSheet("QPushButton { background-color : red }")
                    # TODO: add an automatic refresh of the diff window if changed
        except GitCommandError as err:
            print(err)
            self.git_reachable = False

        self.update_changes_button_colors(repator, diffs)
        return ret_value


    @staticmethod
    def git_changed():
        """Compares DB_VULNS_GIT_UPDATED and DB_VULNS_GIT"""
        try:
            if DB_VULNS_GIT_UPDATED:
                json_db_initial = json.loads(
                    open(DB_VULNS_GIT, 'r').read())["_default"]
                json_db_updated = json.loads(open(DB_VULNS_GIT_UPDATED, 'r').read())["_default"]
                return json_db_updated != json_db_initial
        except FileNotFoundError as err:
            print(err)

            return False

    def timer_vulnerabilities(self):
        """Every REFRESH_RATE seconds, tries to update git."""
        repator = None
        diffs = None
        while True:
            self.git_update()
            time.sleep(REFRESH_RATE)

    def update_changes_button_colors(self, repator, diffs):
        """Updates View changes and refresh colors"""
        view_change_button = repator.layout().itemAt(3).widget()
        if self.vulnerabilities_changed(): # if the vulnerabilities  aren't hidden
            view_change_button.setStyleSheet(
                "QPushButton { background-color : orange }")
        else:
            view_change_button.setStyleSheet(
                "QPushButton { background-color : light gray }")

        git_connection = repator.layout().itemAt(5).widget()
        if self.git_reachable:
            git_connection.setStyleSheet("QLabel { background-color : green }")
        else:
            git_connection.setStyleSheet("QLabel { background-color : red }")

    def refresh(self):
        """Updates git file and refreshes "Diffs" window"""
        if not self.background_update.isAlive():
            self.background_update = Thread(
                target=self.git_update, daemon=True)
            self.background_update.start()
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Diffs":
                window.refresh_tab_widget()

    def git_routine(self):
        """Sets up the git subprocess"""
        self.init_git()
        self.background_thread.start()

    def git_upload(self):
        """
        Uploads to the repo the updated file (vulns)
        """
        self.repo.index.add(DB_VULNS_GIT_FILE)
        self.repo.index.commit('Commit auto')
        self.repo.remote().pull('master')
        self.repo.remote().push('master')
