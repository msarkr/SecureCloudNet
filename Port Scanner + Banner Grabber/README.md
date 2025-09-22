Files in this project
banner_grabber.py – Python script that scans specific host ports and prints any banners or headers the services return. Demonstrates how ports act as entry points and how banners reveal service/version info (useful for CCNA + Sec+ recon basics).
docker-compose.yml – Docker Compose file that defines the lab services (nginx on 8080, sftp/ssh on 2222, ftp on 2121). Provides safe local targets so you don’t scan real systems and keeps the project self-contained.

Problems and fixes
Issue: scanner showed nothing. These commands fixed it:
docker compose down
docker compose pull
docker compose up -d
docker compose ps
Explanation: stop/remove old containers, pull fresh images, start in background, then verify running ports. After this, services responded and the script produced output.

Example run output
PS C:\Users\mohul\yyy> & C:/Users/mohul/yyy "c:/Users/mohul/yyy/banner_grabber.py"
Scanning 127.0.0.1 for banners...
Port 8080: HTTP/1.1 200 OK
Server: nginx/1.29.1
Date: Mon, 22 Sep 2025 00:03:19 GMT
Content-Type: text/html
Content-Length: 615
Last-Modified: Wed, 13 Aug 2025 15:10:23 GMT
Connection: close
ETag: "689caadf-267"
Accept-Ranges: bytes
Port 2222: (no banner or closed)
Port 2121: (no banner or closed)