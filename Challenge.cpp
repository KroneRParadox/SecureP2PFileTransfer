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

static const uint16_t DEFAULT_PORT = 12345;
static const char* PUBKEY_FILE = "public.key";
static const char* PRIVKEY_FILE = "private.key";

SOCKET        connSock = INVALID_SOCKET;
bool          isConnected = false;
RSA::PublicKey peerPub;    // populated by handshake

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

ByteVec readFile(const string& path) {
    ifstream in(path, ios::binary);
    if (!in) throw runtime_error("Cannot open: " + path);
    return ByteVec(istreambuf_iterator<char>(in), {});
}

void writeFile(const string& path, const ByteVec& v) {
    ofstream out(path, ios::binary);
    out.write((char*)v.data(), v.size());
}

void showConnectionStatus() {
    cout << (isConnected ? "[Connected]\n" : "[Disconnected]\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto functions
// ─────────────────────────────────────────────────────────────────────────────

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

RSA::PublicKey loadPub(const string& fn = PUBKEY_FILE) {
    FileSource fs(fn.c_str(), true);
    RSA::PublicKey pub; pub.BERDecode(fs);
    return pub;
}

RSA::PrivateKey loadPriv() {
    FileSource fs(PRIVKEY_FILE, true);
    RSA::PrivateKey priv; priv.BERDecode(fs);
    return priv;
}

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
// Network management
// ─────────────────────────────────────────────────────────────────────────────

void disconnectPeer() {
    if (isConnected) {
        closesocket(connSock);
        WSACleanup();
        isConnected = false;
        cout << "→ Disconnected\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer-side handshake only + file exchange
// ─────────────────────────────────────────────────────────────────────────────

void hostListen() {
    if (isConnected) {
        cout << "Already connected\n";
        return;
    }

    SOCKET listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenFd == INVALID_SOCKET) {
        cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return;
    }
    BOOL opt = TRUE;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DEFAULT_PORT);

    if (::bind(listenFd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
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

    // *** Handshake: receive client's public key ***
    uint32_t netL;
    recv(connSock, (char*)&netL, sizeof(netL), MSG_WAITALL);
    uint32_t L = ntohl(netL);
    ByteVec blob(L);
    recv(connSock, (char*)blob.data(), L, MSG_WAITALL);

    ByteQueue q;
    q.Put(blob.data(), blob.size());
    q.MessageEnd();
    peerPub.BERDecode(q);
    cout << "Handshake: received client pubkey\n";

    isConnected = true;
}

void doConnect() {
    if (isConnected) {
        cout << "Already connected\n";
        return;
    }

    cout << "Server IP: ";
    string ip; cin >> ip;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return;
    }
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(DEFAULT_PORT);
    inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

    if (::connect(s, (sockaddr*)&serv, sizeof(serv)) != 0) {
        cerr << "connect() failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return;
    }
    connSock = s;
    cout << "Connected to server\n";

    // *** Handshake: send our public key ***
    RSA::PublicKey pub = loadPub();
    ByteQueue q;
    pub.DEREncode(q);
    size_t N = q.CurrentSize();
    ByteVec blob(N);
    q.Get(blob.data(), blob.size());

    uint32_t netN = htonl((uint32_t)N);
    send(connSock, (char*)&netN, sizeof(netN), 0);
    send(connSock, (char*)blob.data(), blob.size(), 0);
    cout << "Handshake: sent client pubkey\n";

    isConnected = true;
}

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

    cout << "Sent key(" << ckey.size() << " B) + file("
        << cfile.size() << " B)\n";
}

void receiveEncryptedFile() {
    if (!isConnected) { cout << "Not connected\n"; return; }

    RSA::PrivateKey priv = loadPriv();

    auto recvB = [&](ByteVec& b) {
        uint32_t netL;
        recv(connSock, (char*)&netL, sizeof(netL), MSG_WAITALL);
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
// Submenus & Main
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

    // Auto-generate if missing
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

    return 0;
}
