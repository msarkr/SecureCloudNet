Simple BMP RE Challenge — quick plaintext README

What it is
A tiny demo that generates a 24-bit BMP and injects a short ASCII secret into the pixel bytes (not visible in an image viewer).

Files
rev_eng.py
samples/sample.bmp
screenshots/secret_at_0x36.png

How to run (open PowerShell in the repo folder)

Run the Python script:
python rev_eng.py

Confirm the BMP was created:
dir .\samples\sample.bmp

How to view the hidden secret (PowerShell)
$b = Get-Content .\samples\sample.bmp -Encoding Byte
[System.Text.Encoding]::ASCII.GetString($b, 54, 64)

Open my file screenshot to see what you should see in a hex editor after opening sample.bmp. Other bmp files to mess around with are also avaiable (blackbuck.bmp, bmp_24.bmp, snail.bmp)

Here’s a link to a popular hex editor you can use(File -> Open -> .bmp file):
https://mh-nexus.de/en/hxd/
