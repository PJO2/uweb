
# compute checksums
cd WindowsBinaries && md5sum u*exe  > MD5SUMS && sha1sum u*exe > SHA1SUMS && cd ..

# prepare next shipping
cd ..
git add WindowsBinaries/*
git commit -m "update windows binaries"

# send files to VirusTotal.com for inspection
VT_API_KEY=`cat /home/ark/vt.key`
curl -s  -F 'file=@WindowsBinaries/uweb32.exe' -F apikey=${VT_API_KEY} https://www.virustotal.com/vtapi/v2/file/scan | 
            python -mjson.tool | grep permalink
curl -s  -F 'file=@WindowsBinaries/uweb64.exe' -F apikey=${VT_API_KEY} https://www.virustotal.com/vtapi/v2/file/scan | 
            python -mjson.tool | grep permalink


