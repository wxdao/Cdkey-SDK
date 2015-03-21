#include "cdkeygenerator.h"

#include <pbc/pbc.h>
#include <stdexcept>
#include <openssl/evp.h>
#include "basecoder.h"

#ifdef _WIN32
#include <winsock2.h>
#elif __linux__
#include <arpa/inet.h>
#endif

class CDKeyGeneratorParameters {
public:
    pairing_t pairing;
    element_t g, secret_key;
};

CDKeyGenerator::CDKeyGenerator(std::string pairing, std::string g, std::string secretKey)
{
    OPENSSL_add_all_algorithms_noconf();
    
    param = new CDKeyGeneratorParameters;
    int err;
    if (err = pairing_init_set_str(param->pairing, pairing.c_str())) {
        throw std::invalid_argument("Invalid Pairing.");
    }
    
    element_init_G2(param->g, param->pairing);
    element_init_Zr(param->secret_key, param->pairing);
    
    if (g.length() < element_length_in_bytes_compressed(param->g)) {
        throw std::invalid_argument("Invalid G.");
    }
    if (secretKey.length() < element_length_in_bytes(param->secret_key)) {
        throw std::invalid_argument("Invalid secret key.");
    }
    
    element_from_bytes_compressed(param->g, (byte*)g.data());
    element_from_bytes(param->secret_key, (byte*)secretKey.data());
}

CDKeyGenerator::~CDKeyGenerator()
{
    element_clear(param->g);
    element_clear(param->secret_key);
    pairing_clear(param->pairing);
    delete param;
}

#define MX ((z>>5)^(y<<2)) + (((y>>3)^(z<<4))^(sum^y)) + (k[(p&3)^e]^z);

long btea(long* v, long n, long* k) {
    unsigned long z=v[n-1], y=v[0], sum=0, e, DELTA=0x9e3779b9;
    long p, q ;
    if (n > 1) {          /* Coding Part */
        q = 6 + 52/n;
        while (q-- > 0) {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++) y = v[p+1], z = v[p] += MX;
            y = v[0];
            z = v[n-1] += MX;
        }
        return 0 ; 
    } else if (n < -1) {  /* Decoding Part */
        n = -n;
        q = 6 + 52/n;
        sum = q*DELTA ;
        while (sum != 0) {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--) z = v[p-1], y = v[p] -= MX;
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        return 0;
    }
    return 1;
}

std::string CDKeyGenerator::generate(ulong serial, byte features)
{
    serial = htonl(serial);
    
    element_t h;
    element_t sig;
    
    element_init_G1(h, param->pairing);
    element_init_G1(sig, param->pairing);
    
    ulong sig_sz = element_length_in_bytes_x_only(sig);
    if (sig_sz + 5 < 8) {
        throw std::logic_error("Unable to generate cdkey.");
    }
    
    byte *buf = (byte*)malloc(sig_sz + 5);
    memcpy(buf, &serial, 4);
    memcpy(buf + 4, &features, 1);
    
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit(mdctx, EVP_sha1());
    EVP_DigestUpdate(mdctx, buf, 5);
    byte *hash = (byte*)malloc(EVP_MD_size(EVP_sha1()));
    uint dzlen;
    EVP_DigestFinal(mdctx, hash, &dzlen);
    EVP_MD_CTX_destroy(mdctx);
    
    element_from_hash(h, hash, dzlen);
    element_pow_zn(sig, h, param->secret_key);
    
    element_to_bytes_x_only(buf + 5, sig);
    
    element_t pk;
    element_init_G2(pk, param->pairing);
    element_pow_zn(pk, param->g, param->secret_key);
    
    byte *key;
    key = (byte*)malloc(element_length_in_bytes_compressed(pk) < 16 ? 16 : element_length_in_bytes_compressed(pk));
    element_to_bytes_compressed(key, pk);
    element_clear(pk);
    
    btea((long *)buf, 2, (long *)key);
    
    free(key);
   
    CrockfordCoder cc;
    std::string ret = cc.encode(buf, sig_sz + 5);
    ret = cc.insertSpliter(ret, 6, '-');
    
    element_clear(sig);
    element_clear(h);
    
    free(hash);
    free(buf);
    
    return ret;
}

