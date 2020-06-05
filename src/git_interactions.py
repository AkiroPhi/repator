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
from conf.db import DB_VULNS, DB_VULNS_GIT, DB_VULNS_GIT_UPDATED
from conf.report import SSH_KEY, GIT, REFRESH_RATE


class Git(QObject):
    """Defines interactions between repator and git."""

    def __init__(self):
        super().__init__()
        self.dismiss_changes = False
        self.git_reachable = False
        # ajout perso
        self.repo = None
        self.gitDir = '.tmpGit'
        # the end
        # self.init_git()
        self.app = QCoreApplication.instance()
        self.setParent(self.app)
        self.background_thread = Thread(
            target=self.timer_vulnerabilities, daemon=True)
        self.background_update = Thread(
            target=self.git_update, daemon=True)
        self.git_routine()

    # @staticmethod
    # def execute_command(arg, cwd="."):
    #     """Executes the command arg in a subprocess with the option of setting the cwd."""
    #     process = Popen(arg, shell=True, cwd=cwd, stdout=PIPE, stderr=PIPE)
    #     res = process.communicate()
    #     for line in res:
    #         if line:
    #             result = line.decode('utf-8')
    #             err = findall("[eE][rR][rR][oO][rR]", result)
    #             fat = findall("fatal", result)
    #             if err or fat:
    #                 raise RuntimeError(result)

    def init_git(self):
        """Initialises the git repository in a new directory."""
        self.clean_git()
        self.repo = Repo.init(self.gitDir)
        ssh_cmd = "ssh -i " + SSH_KEY + " -F /dev/null"
        # self.repo.config_writer('core.sshCommand ' + ssh_cmd)
        self.repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd) # set the config ?
        self.repo.create_remote('origin',url=GIT)

    def clean_git(self):
        """Removes the git file (the thread doesn't need to be killed since it is deamonized)."""
        rmtree(self.gitDir)

    @staticmethod
    def vulnerabilities_changed():
        """Compares DB_VULNS and DB_VULNS_GIT"""
        json_db = json.loads(
            open(DB_VULNS, 'r').read())["_default"]
        json_db_updated = json.loads(
            open(DB_VULNS_GIT, 'r').read())["_default"]
        return not json_db_updated == json_db

    def git_update(self):
        """Pulls git repo and colors View changes button if the repository is unreachable."""
        print("Communication with Git...")
        repator, diffs = None, None
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                repator = window
            elif window.windowTitle() == "Diffs":
                diffs = window
        try:
            self.repo.remote().pull('master')
            self.git_reachable = True

        except GitCommandError as err:
            print(err)
            self.git_reachable = False

        self.update_changes_button_colors(repator, diffs)


    @staticmethod
    def git_changed():
        """Compares DB_VULNS_GIT_UPDATED and DB_VULNS_GIT"""
        if DB_VULNS_GIT_UPDATED:
            json_db_initial = json.loads(
                open(DB_VULNS_GIT, 'r').read())["_default"]
            json_db_updated = json.loads(open(DB_VULNS_GIT_UPDATED, 'r').read())[
                "_default"]
            return json_db_updated != json_db_initial
        else:
            return False

    def timer_vulnerabilities(self):
        """Every REFRESH_RATE seconds, tries to update git."""
        repator = None
        diffs = None
        while True:
            self.git_update()
            for window in self.app.topLevelWidgets():
                if window.windowTitle() == "Repator":
                    repator = window
                elif window.windowTitle() == "Diffs":
                    diffs = window
            if self.git_reachable:
                self.update_changes_button_colors(repator, diffs)
            time.sleep(REFRESH_RATE)

    def update_changes_button_colors(self, repator, diffs):
        """Updates View changes and refresh colors"""
        view_change_button = repator.layout().itemAt(3).widget()
        ## repator.dismiss_changes ## (False)
        if not False and Git.vulnerabilities_changed():
            view_change_button.setStyleSheet(
                "QPushButton { background-color : orange }")
        else:
            view_change_button.setStyleSheet(
                "QPushButton { background-color : light gray }")

        if diffs and diffs.isVisible():
                refresh_button = diffs.layout().itemAt(0).widget().widget(0
                ).widget.layout().itemAt(3).widget()
                if Git.git_changed():
                    refresh_button.setStyleSheet("QPushButton { background-color : red }")
                else:
                    refresh_button.setStyleSheet("QPushButton { background-color : light gray }")

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
            if window.windowTitle() == "Diffs" and self.git_reachable:
                copyfile(DB_VULNS_GIT_UPDATED, DB_VULNS_GIT)
                window.refresh_tab_widget()

    def git_routine(self):
        """Sets up the git subprocess"""
        self.init_git()
        print("Git initialise, Lancement de la Maj du repo")
        self.background_thread.start()
