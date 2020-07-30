"""Defines db files and default values"""

# coding=utf-8

import collections

DB_LOCAL_FILES = {}
DB_LOCAL_FILES["vulns"] = "db/vulnerabilities.json"
DB_LOCAL_FILES["auditors"]= "db/auditors.json"
DB_LOCAL_FILES["clients"] = "db/clients.json"

DB_GIT_LOCAL_FILES = {}
DB_GIT_LOCAL_FILES["vulns"] = "db/vulnerabilitiesGit.json"
DB_GIT_LOCAL_FILES["auditors"] = "db/auditorsGit.json"
DB_GIT_LOCAL_FILES["clients"] = "db/clientsGit.json"

DB_GIT_DIR = ".tmpGit/"
DB_GIT_REMOTE_FILES ={}
DB_GIT_REMOTE_FILES["vulns"] = "vulnerabilities.json"
DB_GIT_REMOTE_FILES["auditors"] = "auditors.json"
DB_GIT_REMOTE_FILES["clients"] ="clients.json"

DB_AUDITORS_DEFAULT = collections.OrderedDict()
DB_AUDITORS_DEFAULT["full_name"] = ""
DB_AUDITORS_DEFAULT["phone"] = "+33"
DB_AUDITORS_DEFAULT["email"] = ""
DB_AUDITORS_DEFAULT["role"] = ""

DB_CLIENTS_DEFAULT = collections.OrderedDict()
DB_CLIENTS_DEFAULT["full_name"] = ""
DB_CLIENTS_DEFAULT["phone"] = "+33"
DB_CLIENTS_DEFAULT["email"] = ""
DB_CLIENTS_DEFAULT["role"] = ""

DB_VULNS_DEFAULT = collections.OrderedDict()
DB_VULNS_DEFAULT["category"] = ""
DB_VULNS_DEFAULT["sub_category"] = ""
DB_VULNS_DEFAULT["name"] = ""
DB_VULNS_DEFAULT["labelNeg"] = ""
DB_VULNS_DEFAULT["labelPos"] = ""
DB_VULNS_DEFAULT["observNeg"] = ""
DB_VULNS_DEFAULT["observNegHistory"] = ["New Observation"]
DB_VULNS_DEFAULT["observPos"] = ""
DB_VULNS_DEFAULT["observPosHistory"] = ["New Observation"]
DB_VULNS_DEFAULT["risk"] = ""
DB_VULNS_DEFAULT["riskHistory"] = ["New Risk"]
DB_VULNS_DEFAULT["reco"] = ""
DB_VULNS_DEFAULT["recoHistory"] = ["New Recommandation"]
DB_VULNS_DEFAULT["script"] = ""
DB_VULNS_DEFAULT["regexVuln"] = ""
DB_VULNS_DEFAULT["regexNotVuln"] = ""
DB_VULNS_DEFAULT["AV"] = "Network"
DB_VULNS_DEFAULT["AC"] = "Low"
DB_VULNS_DEFAULT["PR"] = "None"
DB_VULNS_DEFAULT["UI"] = "Required"
DB_VULNS_DEFAULT["S"] = "Unchanged"
DB_VULNS_DEFAULT["C"] = "None"
DB_VULNS_DEFAULT["I"] = "None"
DB_VULNS_DEFAULT["A"] = "None"

DB_VULNS_DIFFERENT_LANG = ["category", "sub_category", "name", "labelNeg", "labelPos", "observNeg", "observNegHistory",
                   "observPos", "observPosHistory", "risk", "riskHistory", "reco", "recoHistory"]
