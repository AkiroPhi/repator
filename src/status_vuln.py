"""defined the calculation of the status of vulnerabilities."""
# coding=utf-8

from collections import defaultdict
from subprocess import Popen, PIPE
import zlib
import re

default_encoding = "utf-8"


class VulnStatus:
    """Defines the automatisation of the status vulnerabilities generator."""

    def __init__(self):
        super().__init__()

        # Index of Popen.communicate return value, and Regex tuplets
        self.indexOutPopen = 0
        self.indexErrPopen = 1
        self.indexRegVuln = 0
        self.indexRegNotVuln = 1
        self.status_na = "NA"
        self.status_todo = "TODO"
        self.status_vuln = "Vulnerable"
        self.status_nvuln = "Not Vulnerable"

        # Internal memory to avoid repetition of calculations
        self.dvalue_std_dict = None
        self.std_dict = defaultdict(lambda: self.dvalue_std_dict)

    def parse_script(self, args: str, tuplet_regex: tuple, encoding=default_encoding) -> tuple:
        """Parse the result of the script executed using args.
        tupletRegex must contain some regex, allowing to define vulnerable and not vulnerable

        Returns a tuplet containing the status of vuln, a boolean saying if the executed script contains
        an error message, and the error message if the boolean is true, None otherwise"""
        stdScript = self.exec_command(args)

        if stdScript is None:
            raise AssertionError("Error, this command is not supported ! : '" + args + "'")

        # Retrieving standard and error outputs
        std_out = stdScript[self.indexOutPopen]
        std_err = stdScript[self.indexErrPopen]

        # If the standart output is not empty, we parse the result
        if not VulnStatus.std_empty(std_out, encoding):

            # We check if the text has already been parsed with the regex tuplet
            # If it's true, we use the registered status
            compressed = None
            try:
                compressed = zlib.compress(std_out)
                if self.std_dict[(compressed, tuplet_regex)] != self.dvalue_std_dict:
                    return self.std_dict[(compressed, tuplet_regex)], not VulnStatus.std_empty(std_err, encoding), std_err
            except zlib.error:
                pass

            # TEXT ENCODING (default : ISO-8859-1)
            # PARSING THE TEXT
            text = VulnStatus.decode_string(std_out, encoding)
            lst_vulns = [False] * len(tuplet_regex)
            for line in text.split("\n"):
                tmp = VulnStatus.check_vuln(line, tuplet_regex)
                for i in range(len(tmp)):
                    if tmp[i]:
                        lst_vulns[i] = True

                # If each regex has been matched, we return the status 'TODO'
                if lst_vulns.count(True) == len(lst_vulns):
                    self.std_dict[(compressed, tuplet_regex)] = self.status_todo
                    return self.status_todo, not VulnStatus.std_empty(std_err, encoding), std_err

            # If no regex has been matched, we return the status 'TODO'
            if lst_vulns.count(True) == 0:
                self.std_dict[(compressed, tuplet_regex)] = self.status_todo
                return self.status_todo, not VulnStatus.std_empty(std_err, encoding), std_err

            # Otherwise, we return the status corresponding to the number of regex matched
            self.std_dict[(compressed, tuplet_regex)] = self.get_status(lst_vulns)
            return self.get_status(lst_vulns), not VulnStatus.std_empty(std_err, encoding), std_err
        else:
            return self.status_todo, False, None

    def get_status(self, lst: list):
        """Returns the status corresponding to the tuplet passed in parameter
            If only the first element is True, we send the status 'VULNERABLE'
            Else if only the last element is True, we send the status 'NOT VULNERABLE'
            Else, we send the status 'ANY'
                This case is only possible if it is a tuplet larger than 2
        """
        if lst[self.indexRegVuln] and not lst[self.indexRegNotVuln]:
            return self.status_vuln
        elif not lst[self.indexRegVuln] and lst[self.indexRegNotVuln]:
            return self.status_nvuln
        return self.status_na

    def exec_command(self, args: str, cwd="."):
        """Execute a child program in a new process, and return """
        process = Popen(args, stdout=PIPE, stderr=PIPE, shell=True, cwd=cwd)
        return process.communicate()

    @staticmethod
    def std_empty(std, encoding=default_encoding):
        """Encode std and returned true if it is empty"""
        return len(VulnStatus.decode_string(std, encoding)) == 0

    @staticmethod
    def decode_string(std, encoding=default_encoding):
        """Returns an encoded texte"""
        return str(std.decode(encoding))

    @staticmethod
    def check_vuln(line, lst_regex: tuple):
        lst_return = []
        for regex in lst_regex:
            lst_return += [True] if re.match(regex, line) else [False]
        return lst_return


status = VulnStatus()

def status_vuln(args, regex, encoding=default_encoding):
    return status.parse_script(args, regex, encoding)