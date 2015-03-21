#ifndef CDKEYGENERATOR_H
#define CDKEYGENERATOR_H

#include <string>
#include <exception>

typedef unsigned long ulong;
typedef unsigned char byte;

class CDKeyGeneratorException : public std::exception {
public:
    enum EID {
        UNKNOWN_ERROR,
        INVALID_PAIRING,
        INVALID_PRIVATE_KEY
    };
    
    explicit CDKeyGeneratorException(EID eid) {
        _eid = eid;
    }

    virtual const char* what() const noexcept {
        switch (_eid) {
        case INVALID_PAIRING:
            return "Invalid pairing parameters.";
        case INVALID_PRIVATE_KEY:
            return "Invalid private key.";
        default:
            return "Unknown error caught.";
        }
    }
private:
    EID _eid = UNKNOWN_ERROR;
};

class CDKeyGeneratorParameters;

class CDKeyGenerator
{
private:
    CDKeyGeneratorParameters *param;
public:
    explicit CDKeyGenerator(std::string pairing, std::string g, std::string secretKey);
    ~CDKeyGenerator();
    
    std::string generate(ulong serial, byte features);
};

#endif // CDKEYGENERATOR_H
