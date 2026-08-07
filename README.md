# FAppBound
FAppBound is a research-oriented proof of concept that demonstrates how Chromium's App-Bound Encryption (ABE) protects browser cookies and how the browser's own privileged decryption mechanism can be invoked from a trusted browser process.

The project consists of two components:
- fappbound.exe – orchestrates the workflow, launches the target browser, communicates with the injected DLL, and decrypts cookie values.
- fappbound.dll – injected into the browser process to invoke Chromium's internal decryption interface and recover the AES key used to protect cookies.

## Features
- Chrome/Edge/Brave support
- Automatic browser detection
- Multiple profile support
- Chromium AppBound (v20) cookie decryption
- Netscape cookie format

## How It Works
1. Read Local State
2. Find app_bound_encrypted_key
3. Launch browser (Suspended)
4. Inject fappbound.dll
5. DecryptData()
6. Recover key
7. Read Cookies from database
8. Decrypt AES-GCM (v20) cookies
9. Export decrypted cookies

## Disclaimer
This repository is provided solely for educational, interoperability, and security research purposes.
It demonstrates the internal operation of Chromium App-Bound Encryption (ABE) and related browser mechanisms.
The author does not encourage or endorse unauthorized access to systems, accounts, or data. Users are solely responsible for complying with applicable laws and the terms of service of any software they interact with.

## License
MIT License
