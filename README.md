# Tactical RMM Windows Agent

[![Build Status](https://travis-ci.com/wh1te909/winagent.svg?branch=master)](https://travis-ci.com/wh1te909/winagent)
[![Build Status](https://dev.azure.com/dcparsi/winagent/_apis/build/status/wh1te909.winagent?branchName=master)](https://dev.azure.com/dcparsi/winagent/_build/latest?definitionId=3&branchName=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

#### Building (powershell, python3.7)

```commandline
mkdir 'C:\Users\Public\Documents\tacticalagent'
cd 'C:\Users\Public\Documents\tacticalagent'
git clone https://github.com/wh1te909/winagent.git .
python -m venv env
.\env\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt
cd winagent
pyinstaller --clean --noconsole --uac-admin --icon=..\bin\onit.ico .\tacticalrmm.py
```

Download and install [Inno Setup](http://jrsoftware.org/isinfo.php)

Open ```setup.iss``` with Inno Setup and compile.

Exe will be in ```C:\Users\Public\Documents\tacticalagent\Output```
