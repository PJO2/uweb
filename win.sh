# a hack script which retrieves the exe from the windows host (using uweb of course)
wget -O WinBinaries/uweb32.exe http://192.168.2.12:8080/Release/uweb.exe
wget -O WinBinaries/uweb64.exe http://192.168.2.12:8080/x64/Release/uweb.exe

# compute checksums
cd WinBinaries
md5sum u*exe  > MD5SUMS
sha1sum u*exe > SHA1SUMS

# prepare next shipping
cd ..
git add WinBinaries/*
git commit -m "update windows binaries"

# send files to VirusTotal.com for inspection
export VT_API_KEY=`cat /home/ark/vt.key`
curl -v -F 'WinBinaries/uweb32.exe' -F apikey=${VT_API_KEY} https://www.virustotal.com/vtapi/v2/file/scan
curl -v -F 'WinBinaries/uweb64.exe' -F apikey=${VT_API_KEY} https://www.virustotal.com/vtapi/v2/file/scan


