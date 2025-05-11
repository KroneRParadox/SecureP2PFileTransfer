# SecureP2PFileTransfer

## Description

SecureP2PFileTransfer is a simple command-line application for Windows that lets two peers exchange files securely. It uses RSA-OAEP (2048-bit) to negotiate a random AES-GCM key, then encrypts the file payload with AES-GCM (256-bit key, 96-bit IV). Designed as a prototype, it’s easy to build on if you need a lightweight secure file exchange.

## Features

* **Automatic RSA key-pair generation** (2048 bits)
* **RSA-OAEP handshake** for secure key exchange
* **AES-GCM encryption/decryption** of file data
* **Peer-to-peer networking** via WinSock2
* **Interactive menu** for local crypto and network operations

## Requirements

* **OS:** Windows 7 or newer
* **Compiler:** Visual Studio (C++17)
* **Libraries:**

  * Crypto++ (cryptlib.lib)
  * WinSock2 (Ws2\_32.lib)

## Build Instructions

1. Open the “Developer Command Prompt for VS”.
2. `cd` into the project directory.
3. Run:

   ```bat
   cl /std:c++17 /EHsc new.cpp /link Ws2_32.lib cryptlib.lib
   ```
4. Launch the executable:

   ```bat
   new.exe
   ```

## Usage

1. On first run, the program generates `public.key` and `private.key`.
2. From the main menu:

   * **1) Local Crypto Tools** – encrypt or decrypt files on your machine.
   * **2) Peer Network** – act as host or connect to a peer for file exchange.
   * **3) Regenerate RSA Key-Pair** – create a new RSA key pair.
   * **0) Exit**
3. In **Peer Network** mode:

   * **Host & Handshake** – listen on port 12345 and wait for a client.
   * **Connect & Handshake** – specify the server IP to connect.
   * After handshake, choose **Send encrypted file** or **Receive encrypted file**.

## Limitations & Roadmap

This is a basic prototype and not intended for production use. Known limitations:

* No detailed error handling or timeouts
* Single-threaded, IPv4 only
* Windows-only implementation

**Future improvements** could include:

* Cross-platform support (Boost.Asio)
* TLS 1.3 integration instead of raw sockets
* Protocol versioning and graceful upgrades
* Graphical interface or REST API

## Contributing

Feel free to fork the project, work on a feature branch, and submit a pull request. Please follow standard GitHub workflow:

```bash
git checkout -b feature/your-feature
# make changes
git commit -am "Add your feature"
git push origin feature/your-feature
```

## License

This project is released under the MIT License. There are no warranties—use at your own risk.
