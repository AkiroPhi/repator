# Repator

Repator is a helper tool designed to automatize the process of report writing, initially for pentesters, but it was developped such that it will be easily customizable for different reporting usage.

## Install

#### Requirements
    Python 3
    Git

### Linux

#### Repator
    git clone https://github.com/lnv42/repator

#### Dependancies
    cd repator
    pip3 install -r requirements.txt 
or

    cd repator
    python3 -m pip install -r requirements.txt

#### Update
    cd repator
    git pull
    pip3 install -r requirements.txt
or

    cd repator
    git pull
    python3 -m pip install -r requirements.txt
    
#### Before the first start

edit the conf/report.py file:

    SSH_KEY = "path/to/your/ssh/key"
    
    GIT = "git@server.com:path/to/vuln.git"
or

    GIT = "https://url.to.repo.of.vulnerabilities.git"
    
#### Start
    cd repator
    ./repator.py
or

    cd repator
    python3 repator.py



### Windows

#### First
Install Python3 https://www.python.org/downloads

Install Git https://git-scm.com/downloads

When you install Python3, you need to check the add Python to PATH box
![image in coming](img/help.png)

#### Repator
Open the git bash (right click in the directory you want the repator --> Git Bash)
    
    git clone https://github.com/AkiroPhi/repator

#### Dependancies
open a console (cmd.exe, powerShell or git bash) in the repator folder
    
    python.exe -m pip install -r requirements.txt
    
#### Update
Open the git bash in the repator folder

    git pull
    python -m pip install -r requirements.txt

#### Before the first start

edit the conf/report.py file:

    SSH_KEY = "path/to/your/ssh/key"
    GIT = "git@server.com:path/to/vuln.git"
or

    GIT = "https://url.to.repo.of.vulnerabilities.git"
    
#### Start

Double-clicked on repator.py file.
Or

    python.exe repator.py
(in the repator folder)
