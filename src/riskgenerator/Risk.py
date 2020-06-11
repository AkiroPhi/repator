"""Defines the calculation of the risk level of vulnerabilities."""
# coding=utf-8

from collections import OrderedDict, defaultdict 
from subprocess import Popen, PIPE
from random import randrange
import sys
import os
import re

class Risk():
    """Defines the automatisation of the rish level generator."""

    def __init__(self):
        super().__init__()

        # Internal memory to avoid repeating calculations
        self.args_dict = OrderedDict()

        # security for Popen, to avoid 'rm'
        self.security_shell = ["(.*\s+(rm)\s+.*)|(^(rm)\s+)|(.*\s+(rm)$)|(rm)"]

        # index of Popen.communicate return value, and Regex tuplets
        self.indexOutPopen = 0
        self.indexErrPopen = 1
        self.indexRegVuln = 0
        self.indexRegNotVuln = 1
        self.risk_any = "ANY"
        self.risk_todo = "TODO"
        self.risk_vuln = "Vulnerable"
        self.risk_nvuln = "Not Vulnerable"
        self.encoding = "utf-8"

    def parseScriptRisk(self, args, tupletRegex):
        """Parse the result of the script executed using args.\n
        tupletRegex must contain some regex, allowing to define vulnerable and not vulnerable"""
        stdScript = self.exec_command(args)
        if stdScript == None:
            raise AssertionError("Error, this command is not supported ! : '" + args + "'")
        
        std_out = stdScript[self.indexOutPopen]
        std_err = stdScript[self.indexErrPopen]
        if not Risk.std_empty(std_err):
            print("/!\ Warning, stderr of the script is not empty /!\\\n\n" +
                Risk.decode_string(std_err) + 
                "\n/!\ Warning, stderr of the script is not empty /!\\")

        if not Risk.std_empty(std_out):
            text = Risk.decode_string(std_out)
            lst_vulns = [False] * len(tupletRegex)
            for line in text.split("\n"):
                tmp = Risk.check_vuln(line, tupletRegex)
                for i in range(len(tmp)):
                    if tmp[i]:
                        lst_vulns[i] = True
                if lst_vulns.count(True) == len(lst_vulns):
                    print("/!\ Each regex have been matched, please check them !/!\\")
                    return (self.risk_todo, not Risk.std_empty(std_err), std_err)

            
            if lst_vulns.count(True) == 0:
                print("/!\ No regex have been matched, please check them !/!\\")
                return (self.risk_todo, not Risk.std_empty(std_err), std_err)
            
            return (self.get_risk(lst_vulns), not Risk.std_empty(std_err), std_err)
                
    def get_risk(self, lst):
        if lst[self.indexRegVuln] and not lst[self.indexRegNotVuln]:
            return self.risk_vuln
        elif not lst[self.indexRegVuln] and lst[self.indexRegNotVuln]:
            return self.risk_nvuln
        return self.risk_any

    def exec_command(self, args, cwd="."):
        if not (self.check_args(args)):
            return None
        process = Popen(args, stdout=PIPE, stderr=PIPE, shell=True, cwd=cwd)
        return process.communicate()

    def check_args(self, args):
        """Vérifie si l'arguments est supporté"""
        if args in self.args_dict:
            return self.args_dict[args]
        
        res = True
        index = 0
        while res and index < len(self.security_shell):
            if re.match(self.security_shell[index], args): 
                res = False
            index += 1
        self.args_dict[args] = res
        return res

    @staticmethod
    def std_empty(std, encoding="ISO-8859-1"):
        return len(Risk.decode_string(std, encoding)) == 0

    @staticmethod
    def decode_string(std, encoding="ISO-8859-1"):
        return str(std.decode(encoding))
    
    @staticmethod
    def check_vuln(line, listRegex):
        lst_return = []
        for regex in listRegex:
            lst_return += [True] if re.match(regex, line) else [False]
        return lst_return
    

if __name__ == "__main__":
    risk = Risk()
    print(risk.parseScriptRisk("C:\\Users\\cleme\\Documents\\generatorText.py", ( ".*(Certificate is not Trusted).*", ".*(Certificate is Trusted).*")))