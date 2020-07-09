"""defined a ping tester."""
# coding=utf-8
import re
import time
from subprocess import Popen, PIPE
from threading import Thread

from PyQt5.QtWidgets import QLineEdit

default_encoding = "utf-8"
REFRESH_RATE_PING = 4

class PingTesterLine(QLineEdit):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.process = None
        self.memory = dict()
        self.currentText = ""
        self.regexConnexion = ".*(4 packets transmitted, 4 received).*"
        self.regexErrConnexion = ".*(4 packets transmitted, 0 received).*"
        self.regexPbmConnexion = ".*(4 packets transmitted, )[1-3]( received).*"
        self.setStyleSheet("QLineEdit { background-color : rgb(150, 150, 150) }")
        self.memory[""] = "rgb(150, 150, 150)"
        self.background_thread = Thread(
            target=self.check_text_thread, daemon=True)
        self.background_thread.start()
        self.textChanged.connect(self.setCurrentText)

    def setCurrentText(self, string=None):
        self.currentText = string

    def check_text_thread(self):
        while True:
            if self.currentText in self.memory.keys():
                text = "QLineEdit { background-color : " + self.memory[self.currentText] + " }"
                self.setStyleSheet(text)
                time.sleep(REFRESH_RATE_PING)
            else:
                self.check()
                time.sleep(REFRESH_RATE_PING)

    def check(self):
        ret_val = False
        if self.process is not None:
            self.process.kill()
        currentText = self.currentText
        self.setStyleSheet("QLineEdit { background-color : rgb(255, 255, 0) }")
        self.process = Popen("ping -c4 -W1 " + currentText, stdout=PIPE, stderr=PIPE, shell=True, cwd=".")
        if self.process is not None:
            stdout, stderr = self.process.communicate()
            if PingTesterLine.std_empty(stderr) and not PingTesterLine.std_empty(stdout):
                ret_val = True
                text = PingTesterLine.decode_string(stdout, default_encoding)
                found = False
                for line in text.split("\n"):
                    if not found:
                        if re.match(self.regexConnexion, line):
                            self.setStyleSheet("QLineEdit { background-color : rgb(40, 220, 40) }")
                            self.memory[currentText] = "rgb(40, 220, 40)"
                            found = True
                        elif re.match(self.regexErrConnexion, line):
                            self.setStyleSheet("QLineEdit { background-color : rgb(230, 42, 42) }")
                            self.memory[currentText] = "rgb(230, 40, 40)"
                            found = True
                        elif re.match(self.regexPbmConnexion, line):
                            self.setStyleSheet("QLineEdit { background-color : rgb(230, 140, 40) }")
                            self.memory[currentText] = "rgb(230, 240, 40)"
                            found = True
                if not found:
                    ret_val = False
                    self.setStyleSheet("QLineEdit { background-color : rgb(150, 150, 150) }")
                    self.memory[currentText] = "rgb(150, 150, 150)"
            else:
                self.setStyleSheet("QLineEdit { background-color : rgb(230, 42, 42) }")
                self.memory[currentText] = "rgb(230, 42, 42)"
        return ret_val

    @staticmethod
    def std_empty(std, encoding=default_encoding):
        """Encode std and returned true if it is empty"""
        return len(PingTesterLine.decode_string(std, encoding)) == 0

    @staticmethod
    def decode_string(std, encoding=default_encoding):
        """Returns an encoded texte"""
        return str(std.decode(encoding))