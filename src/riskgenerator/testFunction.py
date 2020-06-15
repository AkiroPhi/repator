"""Defines the calculation of the risk level of vulnerabilities."""
# coding=utf-8

from collections import OrderedDict, defaultdict 
from subprocess import Popen, PIPE
from random import randrange, sample
import zlib
import sys
import os
import re

default_encoding = "ISO-8859-1"

class Risk():
    """Defines the automatisation of the rish level generator."""

    def __init__(self):
        super().__init__()

        # Security for Popen, to avoid 'rm' for example
        self.security_shell = ["(.*\s+(rm)\s+.*)|(^(rm)\s+)|(.*\s+(rm)$)|(rm)"]

        # Index of Popen.communicate return value, and Regex tuplets
        self.indexOutPopen = 0
        self.indexErrPopen = 1
        self.indexRegVuln = 0
        self.indexRegNotVuln = 1
        self.risk_any = "ANY"
        self.risk_todo = "TODO"
        self.risk_vuln = "Vulnerable"
        self.risk_nvuln = "Not Vulnerable"

        # Internal memory to avoid repetition of calculations
        self.dvalue_std_dict = None
        self.args_dict = OrderedDict()
        self.std_dict = defaultdict(lambda : self.dvalue_std_dict)

    def parseScriptRisk(self, args, tupletRegex):
        """Parse the result of the script executed using args.
        tupletRegex must contain 2 regex, allowing to define
        vulnerable (first regex) and not vulnerable (second regex)"""
        stdScript = self.exec_command(args)

        if stdScript == None:
            raise AssertionError(
                "Error, this command is not supported ! : '" + args + "'")
        
        # Retrieving standard and error outputs
        std_out = stdScript[self.indexOutPopen]
        std_err = stdScript[self.indexErrPopen]

        # If the error output is not empty, you can display it
        if not Risk.std_empty(std_err):
            print("/!\ Warning, stderr of the script is not empty /!\\\n\n" +
                Risk.decode_string(std_err) + 
                "\n/!\ Warning, stderr of the script is not empty /!\\")

        # If the standart output is not empty, we parse the result
        if not Risk.std_empty(std_out):

            # We check if the text has already been parsed with the regex tuplet
            # If it's true, we use the registered risk
            try:
                compressed = zlib.compress(std_out)
                if self.std_dict[(compressed, tupletRegex)] != self.dvalue_std_dict:
                    return (self.std_dict[(compressed, tupletRegex)],
                        not Risk.std_empty(std_err), std_err)
            except:
                pass

            # TEXT ENCODING (default : ISO-8859-1)
            # PARSING THE TEXT
            text = Risk.decode_string(std_out)
            lst_vulns = [False] * len(tupletRegex)
            for line in text.split("\n"):
                tmp = Risk.check_vuln(line, tupletRegex)
                for i in range(len(tmp)):
                    if tmp[i]:
                        lst_vulns[i] = True

                # If each regex has been matched, we return the risk 'TODO'
                if lst_vulns.count(True) == len(lst_vulns):
                    print("/!\ Each regex have been matched, please check them !/!\\")
                    self.std_dict[(compressed, tupletRegex)] = self.risk_todo
                    return (self.risk_todo, not Risk.std_empty(std_err), std_err)

            
            # If no regex has been matched, we return the risk 'TODO'
            if lst_vulns.count(True) == 0:
                print("/!\ No regex have been matched, please check them !/!\\")
                self.std_dict[(compressed, tupletRegex)] = self.risk_todo
                return (self.risk_todo, not Risk.std_empty(std_err), std_err)
            
            # Otherwise, we return the risk corresponding to the number of regex
            #   matched
            self.std_dict[(compressed, tupletRegex)] = self.get_risk(lst_vulns)
            return (self.get_risk(lst_vulns), not Risk.std_empty(std_err), std_err)
                
    def get_risk(self, lst):
        """Returns the risk corresponding to the tuplet passed in parameter
            If only the first element is True, we send the risk 'VULNERABLE'
            Else if only the last element is True, we send the risk 'NOT VULNERABLE'
            Else, we send the risk 'ANY'
                This case is only possible if it is a tuplet larger than 2
        """
        if lst[self.indexRegVuln] and not lst[self.indexRegNotVuln]:
            return self.risk_vuln
        elif not lst[self.indexRegVuln] and lst[self.indexRegNotVuln]:
            return self.risk_nvuln
        return self.risk_any

    def exec_command(self, args, cwd="."):
        """Execute a child program in a new process, and return the communication"""
        if not (self.check_args(args)):
            return None
        process = Popen(args, stdout=PIPE, stderr=PIPE, shell=True, cwd=cwd)
        t = process.communicate()
        return t

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
    def std_empty(std, encoding=default_encoding):
        """Encode std and returned true if it is empty"""
        return len(Risk.decode_string(std, encoding)) == 0

    @staticmethod
    def decode_string(std, encoding=default_encoding):
        """Returns an encoded texte"""
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

