# Tactical RMM Windows Agent

[![Build Status](https://travis-ci.com/wh1te909/winagent.svg?branch=master)](https://travis-ci.com/wh1te909/winagent)
[![Build Status](https://dev.azure.com/dcparsi/winagent/_apis/build/status/wh1te909.winagent?branchName=master)](https://dev.azure.com/dcparsi/winagent/_build/latest?definitionId=3&branchName=master)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

#### Building (powershell, python 3.8.5)

Download and install [Inno Setup](http://jrsoftware.org/isinfo.php)

```commandline
mkdir 'C:\Users\Public\Documents\tacticalagent'
cd 'C:\Users\Public\Documents\tacticalagent'
git clone https://github.com/wh1te909/winagent.git .
python -m venv env
.\env\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install --upgrade setuptools==49.6.0 wheel==0.35.1
pip install --no-cache-dir -r requirements.txt
python .\env\Scripts\pywin32_postinstall.py -install
.\build.ps1
```

Exe will be in ```C:\Users\Public\Documents\tacticalagent\Output```
