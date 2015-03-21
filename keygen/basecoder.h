#ifndef BASECODER_H
#define BASECODER_H

#include <cstring>
#include <string>
#include <cstdlib>
#include <cmath>

typedef unsigned char byte;
typedef unsigned int uint;

class BaseMapper
{
public:
    virtual byte getUnit()
    {
    }
    virtual char mapNA(byte)
    {
    }
    virtual short mapAN(char)
    {
    }
};

template < class _Mapper > class BaseCoder
{
public:
    _Mapper mapper;
    std::string encode(std::string byteString)
    {
        byte unit = mapper.getUnit();
        byte t = 0;
        byte l = 0;
        std::string ret;
        for (byte i:byteString)
        {
            for (byte j = 0; j < 8; ++j)
            {
                t |= i & 1 << (7 - j) ? 1 : 0;
                ++l;
                if (l == 5)
                {
                    ret += mapper.mapNA(t);
                    t = l = 0;
                }
                else
                {
                    t <<= 1;
                }
            }
        }
        if (l)
        {
            t <<= unit - l - 1;
            ret += mapper.mapNA(t);
        }
        return ret;
    }
    std::string encode(byte * byteArray, std::size_t length)
    {
        return encode(std::string((char *)byteArray, length));
    }
    
    std::string decode(std::string str)
    {
        byte unit = mapper.getUnit();
        std::string ret;
        byte p = 0;
        short c;
        byte l = 8;
        byte n;
        for (char i:str)
        {
            c = mapper.mapAN(i);
            if (c == -1)
            {
                return "";
            }
            if (l > unit)
            {
                p |= c << (l - unit);
                l -= unit;
            }
            else
            {
                p |= c >> (unit - l);
                ret += p;
                p = 0;
                p |= c << (8 - unit + l);
                l = 8 - unit + l;
            }
        }
        return ret;
    }
    std::size_t decode(std::string str, byte * buffer,
                       std::size_t bufferLength)
    {
        std::string ret = decode(str);
        if (buffer == NULL)
        {
            return ret.length();
        }
        if (bufferLength < ret.length())
        {
            return 0;
        }
        std::size_t pos = 0;
        for (byte i:ret)
        {
            buffer[pos++] = i;
        }
        return ret.length();
    }
    
    std::string insertSpliter(std::string str, uint interval, char spliter)
    {
        std::string ret;
        if (interval == 0)
        {
            return str;
        }
        uint p = interval;
        for (uint i = 0; i < str.length(); ++i)
        {
            ret += str[i];
            if (--p == 0)
            {
                if (i != str.length() - 1)
                {
                    ret += spliter;
                    p = interval;
                }
            }
        }
        return ret;
    }
};

class CrockfordMapper:public virtual BaseMapper
{
private:
    char alphabet[32] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
        'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X',
        'Y', 'Z'
    };
public:
    
    inline byte getUnit()
    {
        return 5;
    }
    
    char mapNA(byte n)
    {
        return n > 31 ? '?' : alphabet[n];
    };
    short mapAN(char a)
    {
        if (!std::isalnum(a))
        {
            return -1;
        }
        char p = std::toupper(a);
        while (1)
        {
            switch (p)
            {
            case 'U':
                return -1;
            case 'L':
            case 'I':
                p = '1';
                break;
            case 'O':
                p = '0';
                break;
            default:
                for (char i = 0; i < 32; ++i)
                {
                    if (alphabet[i] == p)
                    {
                        return i;
                    }
                }
            }
        }
        return -1;
    }
};

typedef BaseCoder < CrockfordMapper > CrockfordCoder;

#endif // BASECODER_H
