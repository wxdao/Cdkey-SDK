#include <iostream>
#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>

#include <pbc/pbc.h>
#include "basecoder.h"
#include "cdkeygenerator.h"

#ifdef _WIN32
#include <winsock2.h>
#elif __linux__
#include <arpa/inet.h>
#endif

using namespace std;

#define prt(x) cout << x << endl
#define err(x) cerr << x << endl

const char *p160 = 
        "type f \
        q 205523667896953300194896352429254920972540065223 \
        r 205523667896953300194895899082072403858390252929 \
        b 24621211262934046864420303206119860716829523761 \
        beta 187562350206075092254481317379921200936345133422 \
        alpha0 94495776223157076957875806002845406682915769752 \
        alpha1 24554763047888435675509572573619444239620411027";
        
const char *p128 = 
        "type f \
        q 47852219123415845512185342363549838483 \
        r 47852219123415845505267812524159913869 \
        b 5777935917576060097589239245901790486 \
        beta 20167984776237230527929844985440825653 \
        alpha0 9927380017514282786805184102749357849 \
        alpha1 25719000636166423481846408360422374335";

string dir;
byte features = 0;
unsigned long count = 0;
int mode = 0;

void print_help() {
    err("Usage:");
    err("--create                       : Setup new CDKey generator");
    err("--dir, -d <dir>                : CDKey generator directory (must specify)");
    err("--features, -f <binary_string> : Features attached on CDKey (8 bit)");
    err("--count, -c <num>              : How many CDKeys to generate");
    err("--help, -h                     : Print this message");
}

int setup() {
    
#ifdef _WIN32
    if (mkdir(dir.c_str())) {
        err("Directory invalid or already exists");
        return 4;
    }
#elif __linux__
    if (mkdir(dir.c_str(), 0700)) {
        err("Directory invalid or already exists");
        return 4;
    }
#endif
    cout << "Choose key strength(1 - 128bit, 2 - 160bit):";
    int c;
    cin >> c;
    if (c != 1 && c != 2) {
        err("Invalid choice.");
        return 3;
    }
    pairing_t p;
    if (c == 1) {
        pairing_init_set_str(p , p128);
    } else if (c == 2) {
        pairing_init_set_str(p , p160);
    }
    element_t pk,sk,g;
    element_init_G2(g, p);
    element_init_G2(pk, p);
    element_init_Zr(sk, p);
    
    element_random(g);    
    element_random(sk);
    element_pow_zn(pk, g, sk);
    
    byte buf[100];
    FILE *f;
    long len;
    f = fopen((dir + "/pairing.param").c_str(), "w");
    if (c == 1) {
        fwrite(p128, 1, strlen(p128), f);
    } else if (c == 2) {
        fwrite(p160, 1, strlen(p160), f);
    }
    fclose(f);
    f = fopen((dir + "/g.bin").c_str(), "w");
    len = element_length_in_bytes_compressed(g);
    element_to_bytes_compressed(buf, g);
    fwrite(buf, 1, len, f);
    fclose(f);
    f = fopen((dir + "/public_key.bin").c_str(), "w");
    len = element_length_in_bytes_compressed(pk);
    element_to_bytes_compressed(buf, pk);
    fwrite(buf, 1, len, f);
    fclose(f);
    f = fopen((dir + "/secret_key.bin").c_str(), "w");
    len = element_length_in_bytes(sk);
    element_to_bytes(buf, sk);
    fwrite(buf, 1, len, f);
    fclose(f);
    f = fopen((dir + "/serial").c_str(), "w");
    {
        long tmp = 0;
        fwrite(&tmp, 1, 4, f);
    }
    fclose(f);
    element_clear(g);
    element_clear(pk);
    element_clear(sk);
    pairing_clear(p);
}

int gen() {
    FILE *f;
    f = fopen((dir + "/serial").c_str(), "r");
    ulong serial;
    fread(&serial, 1, 4, f);
    serial = ntohl(serial);
    fclose(f);
    
    byte buf[1024];
    pairing_t p;
    f = fopen((dir + "/pairing.param").c_str(), "r");
    ulong sz;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    if (sz > 1024) {
        err("File too large.");
        return 10;
    }
    fseek(f, 0, SEEK_SET);
    fread(buf, 1, sz, f);
    string pairing;
    pairing.assign((char*)buf, sz);
    fclose(f);
    
    f = fopen((dir + "/g.bin").c_str(), "r");
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    if (sz > 1024) {
        err("File too large.");
        return 10;
    }
    fseek(f, 0, SEEK_SET);
    fread(buf, 1, sz, f);
    string g;
    g.assign((char*)buf, sz);
    fclose(f);
    
    f = fopen((dir + "/secret_key.bin").c_str(), "r");
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    if (sz > 1024) {
        err("File too large.");
        return 10;
    }
    fseek(f, 0, SEEK_SET);
    fread(buf, 1, sz, f);
    string sk;
    sk.assign((char*)buf, sz);
    fclose(f);
    
    CDKeyGenerator cdgen(pairing, g, sk);
    
    string cdkey;
    f = fopen((dir + "/cdkeys").c_str(), "a");
    for (ulong i = 0; i < count; ++i) {
        cdkey = cdgen.generate(++serial, features);
        fprintf(f, "%s features:", cdkey.c_str());
        for (int x = 0; x < 8; ++x) {
            if (features & 1 << (8 - x - 1)) {
                fprintf(f, "%c", '1');
            } else {
                fprintf(f, "%c", '0');
            }
        }
        fprintf(f , "\n");
        prt(cdkey);
    }
    fclose(f);
    
    f = fopen((dir + "/serial").c_str(), "w");
    serial = htonl(serial);
    fwrite(&serial, 1, 4, f);
    fclose(f);
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        print_help();
        return 1;
    }
    
    const char *short_opts = "d:f:c:h";
    struct option long_opts[] = {
    {"create", no_argument, NULL, 200},
    {"dir", required_argument, NULL, 'd'},
    {"features", required_argument, NULL, 'f'},
    {"count", required_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'}};
    int c;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
        case 200:
            mode = 1;
            break;
        case 'd':
            dir = optarg;
            break;
        case 'f':
            features = byte(strtol(optarg, 0, 2));
            break;
        case 'c':
            count = strtoul(optarg, 0, 10);
            mode = 2;
            break;
        case 'h':
            print_help();
            break;
        default:
            err("Unknown paramater.");
            print_help();
            return 1;
            break;
        }
    }
    
    if (dir.empty()) {
        err("Must specify dir.");
        return 1;
    }
    
    if (mode == 1) {
        return setup();
    } else if (mode == 2) {
        return gen();
    } else {
        err("No operation.");
    }
   
    return 0;
}

