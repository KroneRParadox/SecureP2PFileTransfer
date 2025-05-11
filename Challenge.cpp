// new.cpp
// Build with: C++17, link Ws2_32.lib and cryptlib.lib
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <limits>

using namespace std;
using namespace CryptoPP;
using ByteVec = vector<byte>;

// Default listening/connecting port and key file paths
static const uint16_t DEFAULT_PORT = 12345;
static const char* PUBKEY_FILE = "public.key";
static const char* PRIVKEY_FILE = "private.key";

// Global socket and connection state
SOCKET        connSock = INVALID_SOCKET;
bool          isConnected = false;
RSA::PublicKey peerPub;    // Will hold the peer's RSA public key from handshake

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: file IO and connection status display
// ─────────────────────────────────────────────────────────────────────────────

// Read entire binary file into ByteVec
ByteVec readFile(const string& path) {
    ifstream in(path, ios::binary);
    if (!in) throw runtime_error("Cannot open: " + path);
    return ByteVec(istreambuf_iterator<char>(in), {});
}

// Write ByteVec content out to binary file
void writeFile(const string& path, const ByteVec& v) {
    ofstream out(path, ios::binary);
    out.write((char*)v.data(), v.size());
}

// Print connection status to console
void showConnectionStatus() {
    cout << (isConnected ? "[Connected]\n" : "[Disconnected]\n");
}


// ─────────────────────────────────────────────────────────────────────────────
// Crypto functions: RSA keygen, load, encrypt/decrypt, AES-GCM encrypt/decrypt
// ─────────────────────────────────────────────────────────────────────────────

// Generate RSA key pair and write to files
void genRSAKeys() {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    RSA::PrivateKey priv(params);
    RSA::PublicKey  pub(params);

    FileSink fsPriv(PRIVKEY_FILE);
    priv.DEREncode(fsPriv);

    FileSink fsPub(PUBKEY_FILE);
    pub.DEREncode(fsPub);

    cout << "Generated RSA key-pair:\n"
        << "  Public:  " << PUBKEY_FILE << "\n"
        << "  Private: " << PRIVKEY_FILE << "\n";
}

// Load public key from file
RSA::PublicKey loadPub(const string& fn = PUBKEY_FILE) {
    FileSource fs(fn.c_str(), true);
    RSA::PublicKey pub; pub.BERDecode(fs);
    return pub;
}

// Load private key from file
RSA::PrivateKey loadPriv() {
    FileSource fs(PRIVKEY_FILE, true);
    RSA::PrivateKey priv; priv.BERDecode(fs);
    return priv;
}

// RSA-OAEP encrypt
ByteVec rsaEncrypt(const RSA::PublicKey& K, const ByteVec& pt) {
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Encryptor enc(K);
    ByteVec ct;
    StringSource(
        pt.data(), pt.size(), true,
        new PK_EncryptorFilter(rng, enc, new VectorSink(ct))
    );
    return ct;
}

// RSA-OAEP decrypt
ByteVec rsaDecrypt(const RSA::PrivateKey& K, const ByteVec& ct) {
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Decryptor dec(K);
    ByteVec pt;
    StringSource(
        ct.data(), ct.size(), true,
        new PK_DecryptorFilter(rng, dec, new VectorSink(pt))
    );
    return pt;
}

// AES-GCM encrypt
ByteVec aesGcmEncrypt(const ByteVec& key, const ByteVec& iv, const ByteVec& pt) {
    GCM<AES>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    ByteVec ct;
    AuthenticatedEncryptionFilter ef(
        e,
        new VectorSink(ct),
        /*putIVfirst=*/false,
        AES::BLOCKSIZE
    );
    ef.ChannelPut("", pt.data(), pt.size());
    ef.ChannelMessageEnd("");
    return ct;
}

// AES-GCM decrypt & verify
ByteVec aesGcmDecrypt(const ByteVec& key, const ByteVec& iv, const ByteVec& ct) {
    GCM<AES>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    ByteVec pt;
    AuthenticatedDecryptionFilter df(
        d,
        new VectorSink(pt),
        AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        AES::BLOCKSIZE
    );
    df.ChannelPut("", ct.data(), ct.size());
    df.ChannelMessageEnd("");
    return pt;
}

// ─────────────────────────────────────────────────────────────────────────────
// Network management: disconnect cleanly
// ─────────────────────────────────────────────────────────────────────────────

void disconnectPeer() {
    if (isConnected) {
        closesocket(connSock);
        isConnected = false;
        cout << "→ Disconnected\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer handshake & file-exchange routines
// ─────────────────────────────────────────────────────────────────────────────

// Host: wait, handshake (recv client's pubkey)
void hostListen() {
    if (isConnected) {
        cout << "Already connected\n";
        return;
    }

    SOCKET listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOL opt = TRUE;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(DEFAULT_PORT);

    if (::bind(listenFd, (sockaddr*)&srv, sizeof(srv)) == SOCKET_ERROR) {
        cerr << "bind() failed: " << WSAGetLastError() << "\n";
        closesocket(listenFd);
        return;
    }
    if (listen(listenFd, 1) == SOCKET_ERROR) {
        cerr << "listen() failed: " << WSAGetLastError() << "\n";
        closesocket(listenFd);
        return;
    }

    cout << "Listening on port " << DEFAULT_PORT << " …\n";
    connSock = accept(listenFd, nullptr, nullptr);
    closesocket(listenFd);
    if (connSock == INVALID_SOCKET) {
        cerr << "accept() failed: " << WSAGetLastError() << "\n";
        return;
    }
    cout << "Client connected\n";

    // 1) Receive client's public key
    uint32_t netLen;
    recv(connSock, (char*)&netLen, sizeof(netLen), MSG_WAITALL);
    uint32_t len = ntohl(netLen);
    ByteVec clientBlob(len);
    recv(connSock, (char*)clientBlob.data(), len, MSG_WAITALL);

    ByteQueue q1;
    q1.Put(clientBlob.data(), clientBlob.size());
    q1.MessageEnd();
    peerPub.BERDecode(q1);
    cout << "Handshake: received client pubkey\n";

    // 2) Send server's public key
    RSA::PublicKey serverPub = loadPub();
    ByteQueue q2;
    serverPub.DEREncode(q2);
    size_t sz = q2.CurrentSize();
    ByteVec serverBlob(sz);
    q2.Get(serverBlob.data(), serverBlob.size());

    uint32_t netSz = htonl((uint32_t)sz);
    send(connSock, (char*)&netSz, sizeof(netSz), 0);
    send(connSock, (char*)serverBlob.data(), serverBlob.size(), 0);
    cout << "Handshake: sent server pubkey\n";

    isConnected = true;
}

// Client: connect + handshake (send our pubkey)
void doConnect() {
    if (isConnected) {
        cout << "Already connected\n";
        return;
    }

    cout << "Server IP: ";
    string ip; cin >> ip;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(DEFAULT_PORT);
    inet_pton(AF_INET, ip.c_str(), &srv.sin_addr);

    if (::connect(s, (sockaddr*)&srv, sizeof(srv)) != 0) {
        cerr << "connect() failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return;
    }
    connSock = s;
    cout << "Connected to server\n";

    // 1) Send client's public key
    RSA::PublicKey clientPub = loadPub();
    ByteQueue q1;
    clientPub.DEREncode(q1);
    size_t sz = q1.CurrentSize();
    ByteVec blob(sz);
    q1.Get(blob.data(), blob.size());

    uint32_t netSz = htonl((uint32_t)sz);
    send(connSock, (char*)&netSz, sizeof(netSz), 0);
    send(connSock, (char*)blob.data(), blob.size(), 0);
    cout << "Handshake: sent client pubkey\n";

    // 2) Receive server's public key
    uint32_t netLen;
    recv(connSock, (char*)&netLen, sizeof(netLen), MSG_WAITALL);
    uint32_t len = ntohl(netLen);
    ByteVec serverBlob(len);
    recv(connSock, (char*)serverBlob.data(), len, MSG_WAITALL);

    ByteQueue q2;
    q2.Put(serverBlob.data(), serverBlob.size());
    q2.MessageEnd();
    peerPub.BERDecode(q2);
    cout << "Handshake: received server pubkey\n";

    isConnected = true;
}

// Send a file under AES-GCM, key+IV wrapped by RSA
void sendEncryptedFile() {
    if (!isConnected) { cout << "Not connected\n"; return; }

    cout << "File to send: ";
    string path; cin >> path;
    auto pt = readFile(path);

    AutoSeededRandomPool rng;
    ByteVec key(32), iv(12);
    rng.GenerateBlock(key.data(), key.size());
    rng.GenerateBlock(iv.data(), iv.size());

    auto cfile = aesGcmEncrypt(key, iv, pt);

    ByteVec blob;
    blob.insert(blob.end(), key.begin(), key.end());
    blob.insert(blob.end(), iv.begin(), iv.end());
    auto ckey = rsaEncrypt(peerPub, blob);

    auto sendB = [&](const ByteVec& b) {
        uint32_t L = htonl((uint32_t)b.size());
        send(connSock, (char*)&L, sizeof(L), 0);
        send(connSock, (char*)b.data(), b.size(), 0);
        };
    sendB(ckey);
    sendB(cfile);

    cout << "Sent key(" << ckey.size() << " B) + file(" << cfile.size() << " B)\n";
}

// Receive RSA-wrapped AES key+IV, then AES-GCM file
void receiveEncryptedFile() {
    if (!isConnected) { cout << "Not connected\n"; return; }

    RSA::PrivateKey priv = loadPriv();

    auto recvB = [&](ByteVec& b) {
        uint32_t netL; recv(connSock, (char*)&netL, sizeof(netL), MSG_WAITALL);
        uint32_t L = ntohl(netL);
        b.resize(L);
        recv(connSock, (char*)b.data(), L, MSG_WAITALL);
        };
    ByteVec ckey, cfile;
    recvB(ckey);
    recvB(cfile);

    auto blob = rsaDecrypt(priv, ckey);
    ByteVec key(blob.begin(), blob.begin() + 32),
        iv(blob.begin() + 32, blob.end());

    cout << "Save raw encrypted? (y/n): ";
    char yn; cin >> yn;
    if (yn == 'y' || yn == 'Y') {
        cout << "Filename [encrypted.bin]: ";
        string f;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        getline(cin, f);
        if (f.empty()) f = "encrypted.bin";
        writeFile(f, cfile);
        cout << "→ " << f << "\n";
    }

    ByteVec pt;
    try {
        pt = aesGcmDecrypt(key, iv, cfile);
    }
    catch (const Exception& e) {
        cerr << "AES-GCM decrypt failed: " << e.what() << "\n";
        return;
    }

    cout << "Save plaintext [out.bin]: ";
    string f; getline(cin, f);
    if (f.empty()) f = "out.bin";
    writeFile(f, pt);
    cout << "→ " << f << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Menus
// ─────────────────────────────────────────────────────────────────────────────

void localCryptoMenu() {
    int c;
    do {
        showConnectionStatus();
        cout << "\n=== Local Crypto Tools ===\n"
            "1) AES-GCM Encrypt file\n"
            "2) AES-GCM Decrypt file\n"
            "3) RSA Encrypt file\n"
            "4) RSA Decrypt file\n"
            "0) Back\n"
            "Choice: ";
        cin >> c; cin.ignore(numeric_limits<streamsize>::max(), '\n');

        try {
            switch (c) {
            case 1: {
                cout << "File to encrypt: "; string in; cin >> in;
                auto pt = readFile(in);
                AutoSeededRandomPool rng;
                ByteVec key(32), iv(12);
                rng.GenerateBlock(key.data(), key.size());
                rng.GenerateBlock(iv.data(), iv.size());
                auto ct = aesGcmEncrypt(key, iv, pt);
                cout << "Save as: "; string out; cin >> out;
                writeFile(out, ct);
                cout << "Key(hex): "; HexEncoder enc(new FileSink(cout));
                enc.Put(key.data(), key.size()); enc.MessageEnd();
                cout << "\nIV (hex): "; enc.Put(iv.data(), iv.size()); enc.MessageEnd();
                cout << "\n";
                break;
            }
            case 2: {
                cout << "File to decrypt: "; string in; cin >> in;
                auto ct = readFile(in);
                cout << "Key(hex): "; string kh; cin >> kh;
                cout << "IV (hex): "; string ih; cin >> ih;
                ByteVec key, iv;
                StringSource(kh, true, new HexDecoder(new VectorSink(key)));
                StringSource(ih, true, new HexDecoder(new VectorSink(iv)));
                auto pt = aesGcmDecrypt(key, iv, ct);
                cout << "Save as: "; string out; cin >> out;
                writeFile(out, pt);
                break;
            }
            case 3: {
                cout << "File to RSA-encrypt: "; string in; cin >> in;
                auto pt = readFile(in);
                cout << "Peer pubkey [public.key]: "; string pk; cin >> pk;
                auto pub = loadPub(pk);
                auto ct = rsaEncrypt(pub, pt);
                cout << "Save as: "; string out; cin >> out;
                writeFile(out, ct);
                break;
            }
            case 4: {
                cout << "File to RSA-decrypt: "; string in; cin >> in;
                auto ct = readFile(in);
                auto pt = rsaDecrypt(loadPriv(), ct);
                cout << "Save as: "; string out; cin >> out;
                writeFile(out, pt);
                break;
            }
            case 0: break;
            default: cout << "Invalid\n";
            }
        }
        catch (const exception& e) {
            cerr << "Error: " << e.what() << "\n";
        }
    } while (c != 0);
}

void networkMenu() {
    int c;
    do {
        // ─── Peek to detect a remote, orderly shutdown ────────────────────
        if (isConnected) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(connSock, &readfds);
            TIMEVAL tv = { 0, 0 };
            int sel = select(0, &readfds, nullptr, nullptr, &tv);
            if (sel > 0 && FD_ISSET(connSock, &readfds)) {
                char buf;
                int r = ::recv(connSock, &buf, 1, MSG_PEEK);
                if (r == 0) {
                    cout << "→ Peer disconnected\n";
                    closesocket(connSock);
                    isConnected = false;
                }
            }
        }

        showConnectionStatus();
        cout << "\n=== Peer Network ===\n";
        if (!isConnected) {
            cout << "1) Host & handshake\n"
                "2) Connect & handshake\n"
                "0) Back\n"
                "Choice: ";
        }
        else {
            cout << "1) Send encrypted file\n"
                "2) Receive encrypted file\n"
                "3) Disconnect\n"
                "0) Back\n"
                "Choice: ";
        }
        cin >> c; cin.ignore(numeric_limits<streamsize>::max(), '\n');

        try {
            if (!isConnected) {
                if (c == 1) hostListen();
                else if (c == 2) doConnect();
                else if (c != 0) cout << "Invalid\n";
            }
            else {
                if (c == 1) sendEncryptedFile();
                else if (c == 2) receiveEncryptedFile();
                else if (c == 3) disconnectPeer();
                else if (c != 0) cout << "Invalid\n";
            }
        }
        catch (const exception& e) {
            cerr << "Error: " << e.what() << "\n";
        }
    } while (c != 0);
}

int main() {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        cerr << "WSAStartup failed\n";
        return 1;
    }

    // Auto-generate RSA keys if missing
    if (!ifstream(PRIVKEY_FILE)) {
        genRSAKeys();
    }

    int choice;
    do {
        showConnectionStatus();
        cout << "\n=== Main Menu ===\n"
            "1) Local Crypto Tools\n"
            "2) Peer Network\n"
            "3) Regenerate RSA Key-Pair\n"
            "0) Exit\n"
            "Choice: ";
        cin >> choice; cin.ignore(numeric_limits<streamsize>::max(), '\n');
        switch (choice) {
        case 1: localCryptoMenu(); break;
        case 2: networkMenu();     break;
        case 3: genRSAKeys();      break;
        case 0: disconnectPeer();  break;
        default: cout << "Invalid\n";
        }
    } while (choice != 0);

    WSACleanup();
    return 0;
}
