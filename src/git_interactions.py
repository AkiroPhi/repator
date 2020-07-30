"""Defines Git class, a helper to use Git."""
# coding=utf-8
from shutil import rmtree
from git import Repo, GitCommandError
from os import mkdir, chmod, unlink
from stat import S_IWRITE

from subprocess import Popen, PIPE
from re import findall
import json
import time
from threading import Thread
from shutil import copyfile
from PyQt5.QtCore import QCoreApplication, QObject
from conf.db import DB_LOCAL_FILES, DB_GIT_LOCAL_FILES,  DB_GIT_DIR, DB_GIT_REMOTE_FILES
from conf.report import SSH_KEY, GIT, REFRESH_RATE, COMMIT_MESSAGE


class Git(QObject):
    """Defines interactions between repator and git."""

    def __init__(self):
        super().__init__()
        self.git_reachable = False
        self.repo = None
        self.app = QCoreApplication.instance()
        self.setParent(self.app)
        self.hidden_changes_objects = {"vulns":set(), "auditors":set(), "clients":set()}
        self.background_thread = Thread(
            target=self.timer_vulnerabilities, daemon=True)
        self.background_update = Thread(
            target=self.git_update, daemon=True)
        self.git_routine()

    def init_git(self):
        """Initialises the git repository in a new directory."""
        self.clean_git()
        self.repo = Repo.init(DB_GIT_DIR)
        ssh_cmd = "ssh -i " + SSH_KEY + " -F /dev/null -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=no"
        self.repo.git.update_environment(GIT_SSH_COMMAND=ssh_cmd) # set the config ?
        self.repo.create_remote('origin', url=GIT)

    def clean_git(self):
        """Removes the git file (the thread doesn't need to be killed since it is deamonized)."""
        def on_rm_error(func, path, exc_info):
            chmod(path, S_IWRITE)
            unlink(path)

        try:
            rmtree(DB_GIT_DIR, onerror=on_rm_error)
        except FileNotFoundError:
            pass

    def vulnerabilities_changed(self): #useless
        """
        Compares DB_LOCAL_FILES["vulns"] and DB_VULNS_GIT
        Return True if the vulnerabilities tracked changed
        """
        try:
            json_db = json.loads(
                open(DB_LOCAL_FILES["vulns"], 'r').read())["_default"]
            json_db_git = json.loads(
                open(DB_GIT_LOCAL_FILES["vulns"], 'r').read())["_default"]
        except FileNotFoundError:
            return True
        list_id = set(json_db.keys()).union(set((json_db_git.keys())))
        for ident in list_id:
            if ident not in self.hidden_changes_objects["vulns"] and (ident not in json_db or ident not in json_db_git or  json_db_git[ident] != json_db[ident]):
                return True
        return False

    def objects_changed(self, db_local_file, db_git_file, obj):
        try:
            json_db = json.loads(
                open(db_local_file, 'r').read())["_default"]
            json_db_git = json.loads(
                open(db_git_file, 'r').read())["_default"]
        except FileNotFoundError:
            return True
        list_id = set(json_db.keys()).union(set((json_db_git.keys())))
        for ident in list_id:
            if ident not in self.hidden_changes_objects[obj] and (ident not in json_db or ident not in json_db_git or  json_db_git[ident] != json_db[ident]):
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

            objects_changed = Git.git_changed()
            if diffs:
                refresh_button = diffs.grid.itemAt(1).widget()
                refresh_button.setStyleSheet("QPushButton { background-color : light gray }")
            for ind_object in  objects_changed:
                copyfile(DB_GIT_DIR + DB_GIT_REMOTE_FILES[ind_object] , DB_GIT_LOCAL_FILES[ind_object])
                ret_value = True
                if diffs and diffs.isVisible():
                    refresh_button.setStyleSheet("QPushButton { background-color : red }")
                    # TODO: add an automatic refresh of the diff window if changed
                    # diffs.refresh_tab_widget() --> cause an QObject::setParent: Cannot set parent, new parent is in a different thread

        except GitCommandError as err:
            print(err)
            self.git_reachable = False

        self.update_changes_buttons(repator)
        return ret_value


    @staticmethod
    def git_changed():
        """Compares DB_VULNS_GIT_UPDATED and DB_GIT_LOCAL_FILES["vulns"]"""
        objects_changed = []
        for ind_objects in DB_GIT_REMOTE_FILES:
            try:
                if DB_GIT_DIR + DB_GIT_REMOTE_FILES[ind_objects]:
                    json_db_initial = json.loads(
                        open(DB_GIT_LOCAL_FILES[ind_objects], 'r').read())["_default"]
                    json_db_updated = json.loads(open(DB_GIT_DIR + DB_GIT_REMOTE_FILES[ind_objects], 'r').read())["_default"]
                    objects_changed = objects_changed + [ind_objects] if json_db_updated != json_db_initial else objects_changed
            except FileNotFoundError as err:
                print(err)
        return objects_changed

    def timer_vulnerabilities(self):
        """Every REFRESH_RATE seconds, tries to update git."""
        repator = None
        diffs = None
        while True:
            self.git_update()
            time.sleep(REFRESH_RATE)

    def update_changes_buttons(self, repator):
        """Updates View changes and refresh colors"""
        view_change_button = repator.layout().itemAt(3).widget()
        git_connection = repator.layout().itemAt(5).widget()
        if self.git_reachable:
            git_connection.setStyleSheet("QPushButton { background-color : green }")
            view_change_button.setEnabled(True)
            if self.objects_changed(DB_LOCAL_FILES["vulns"], DB_GIT_LOCAL_FILES["vulns"], "vulns"): # if the vulnerabilities  aren't hidden
                view_change_button.setStyleSheet(
                    "QPushButton { background-color : orange }")
            elif self.objects_changed(DB_LOCAL_FILES["auditors"], DB_GIT_LOCAL_FILES["auditors"], "auditors"): # if the auditors aren't hidden
                view_change_button.setStyleSheet(
                    "QPushButton { background-color : orange }")
            elif self.objects_changed(DB_LOCAL_FILES["clients"], DB_GIT_LOCAL_FILES["clients"], "clients"): # if the clients  aren't hidden
                view_change_button.setStyleSheet(
                    "QPushButton { background-color : orange }")
            else:
                view_change_button.setStyleSheet(
                    "QPushButton { background-color : light gray }")
        else:
            git_connection.setStyleSheet("QPushButton { background-color : red }")
            view_change_button.setStyleSheet(
                "QPushButton { background-color : light gray }")
            view_change_button.setEnabled(False)

    def refresh(self):
        """Updates git file and refreshes "Diffs" window"""
        if not self.background_update.isAlive():
            self.background_update = Thread(
                target=self.git_update, daemon=True)
            self.background_update.start()
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Diffs":
                window.refresh_tab_widget()
            elif window.windowTitle() == "Repator":
                self.update_changes_buttons(window)

    def git_routine(self):
        """Sets up the git subprocess"""
        self.init_git()
        for window in self.app.topLevelWidgets():
            if window.windowTitle() == "Repator":
                git_text = window.layout().itemAt(5).widget()
        git_text.clicked.connect(self.refresh)
        self.background_thread.start()

    def git_upload(self, db_file):
        """
        Uploads to the repo the updated file (vulns)
        """
        self.repo.index.add(db_file)
        self.repo.index.commit(COMMIT_MESSAGE)
        self.repo.remote().pull('master')
        try:
            self.repo.remote().push('master')
        except GitCommandError as err:
            #TODO deal with other error ---> no right to push
            #                           \-->
            if "Authentication failed" in err.stderr:
                self.undo_last_commit()
                # QmessageBox ??
                return False
            else:
                raise err
        return True

    def undo_last_commit(self):
        """
        Undo the last commit (I wish)
        """
        self.repo.head.reset(commit="HEAD~1", working_tree=True)
