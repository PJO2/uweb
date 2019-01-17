# a hack script which retrieves the exe from the windows host (using uweb of course)
wget -O WinBinaries/uweb32.exe http://192.168.2.12:8080/Release/uweb.exe
wget -O WinBinaries/uweb64.exe http://192.168.2.12:8080/x64/Release/uweb.exe
cd WinBinaries
md5sum u*exe > SHA
cd ..
git add WinBinaries/*
git commit -m "update windows binaries"
