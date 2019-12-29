# Tactical RMM Windows Agent

[![Build Status](https://travis-ci.com/wh1te909/winagent.svg?branch=master)](https://travis-ci.com/wh1te909/winagent)
[![Build Status](https://dev.azure.com/dcparsi/winagent/_apis/build/status/wh1te909.winagent?branchName=master)](https://dev.azure.com/dcparsi/winagent/_build/latest?definitionId=3&branchName=master)

#### Building (powershell, python3.7)

```commandline
mkdir 'C:\Users\Public\Documents\tacticalagent'
cd 'C:\Users\Public\Documents\tacticalagent'
git clone https://github.com/wh1te909/winagent.git .
python -m venv env
.\env\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
cd winagent
pyinstaller --clean --noconsole --icon=onit.ico .\tacticalagent.py
pyinstaller --clean --noconsole --icon=onit.ico .\winagentsvc.py
pyinstaller --clean --noconsole --icon=onit.ico .\checkrunner.py
pyinstaller --clean --noconsole --icon=onit.ico .\winupdater.py
pyinstaller --clean --noconsole --onefile --icon=onit.ico .\cleanup.py
```

Download and install [Inno Setup](http://jrsoftware.org/isinfo.php)

Open ```setup.iss``` with Inno Setup and compile.

Exe will be in ```C:\Users\Public\Documents\tacticalagent\Output```
