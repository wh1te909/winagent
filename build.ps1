cd winagent
Remove-Item "__pycache__" -Recurse -ErrorAction Ignore
Remove-Item "build" -Recurse -ErrorAction Ignore
Remove-Item "dist" -Recurse -ErrorAction Ignore
pyinstaller --clean --uac-admin --noupx --icon=..\bin\onit.ico .\tacticalrmm.py
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" ..\setup.iss