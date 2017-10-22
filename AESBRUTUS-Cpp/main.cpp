#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <regex>
#include <codecvt>
#include <thread>
#include "base64.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

using namespace std;

int char2int(char input)
{
    if(input >= '0' && input <= '9')
        return input - '0';
    if(input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

void hex2bin(const char* src, char* target)
{
    while(*src && src[1])
    {
        *(target++) = char2int(*src)*16 + char2int(src[1]);
        src += 2;
    }
}

bool remove_padding(uint8_t* plain, int size){
     uint8_t padding_size = plain[size - 1];

    if(padding_size > size || padding_size > 16 || padding_size <= 0){
        return false;
    }

    for(int i = size - 1; i > size - 1 - padding_size; --i){
        plain[i] = 0;
    }
}


bool utf8_to_iso_string(uint8_t *str, int size)
{
    char new_str[size];
    memset(new_str, 0, size);
    int new_str_it = 0;
    bool utf8 = false;
    for(int i = 0; i < size; ++i){
        if(!utf8){
            if(str[i] < 128){
                new_str[new_str_it] = str[i];
                new_str_it++;
            } else {
                utf8 = true;
            }
        } else {
            utf8 = false;
            switch(str[i-1]){
                case 196:{
                    switch(str[i]) {
                        case 132: new_str[new_str_it] = '•'; break;
                        case 133: new_str[new_str_it] = 'π'; break;
                        case 134: new_str[new_str_it] = '∆'; break;
                        case 135: new_str[new_str_it] = 'Ê'; break;
                        case 152: new_str[new_str_it] = ' '; break;
                        case 153: new_str[new_str_it] = 'Í'; break;
                    }
                } break;
                case 197: {
                    switch(str[i]){
                        case 129: new_str[new_str_it] = '£'; break;
                        case 130: new_str[new_str_it] = '≥'; break;
                        case 131: new_str[new_str_it] = '—'; break;
                        case 132: new_str[new_str_it] = 'Ò'; break;
                        case 178: new_str[new_str_it] = '”'; break;
                        case 179: new_str[new_str_it] = 'Û'; break;
                        case 154: new_str[new_str_it] = 'å'; break;
                        case 155: new_str[new_str_it] = 'ú'; break;
                        case 185: new_str[new_str_it] = 'è'; break;
                        case 186: new_str[new_str_it] = 'ü'; break;
                        case 187: new_str[new_str_it] = 'Ø'; break;
                        case 188: new_str[new_str_it] = 'ø'; break;
                    }
                } break;
            }
            new_str_it++;
        }
    }
    for(int i = 0; i < size; ++i){
        str[i] = (uint8_t)new_str[i];
    }
    return str;
}

void make_key(uint8_t* suffix, int suffix_len, uint8_t* key, uint8_t threadStart, uint8_t start){
    int bytes_needed = 32 - suffix_len;

    memset(key, 0, bytes_needed);

    for(int i = 0; i < suffix_len; ++i){
        key[i + bytes_needed] = suffix[i];
    }

    key[bytes_needed - 1] += threadStart;

    key[0] += start;
}

void increase_key(uint8_t* key, int bytes_needed, uint8_t thread, uint8_t threads){
    int start_byte = bytes_needed - 1;
    for(int i = start_byte; i >= 0;){
        if(i == start_byte){
            key[i] += threads;
            if(key[i] == thread){
                i--;
            } else {
                break;
            }
        } else {
            key[i]++;
            if(key[i] == 0){
                i--;
            } else {
                break;
            }
        }
    }
}

void thread_decrypt(uint8_t* decoded_msg2, int decoded_msg_len, uint8_t* iv2, int iv_len, uint8_t* suffix2, int suffix_len, uint8_t start, uint8_t stop, uint8_t thread, uint8_t threads){
    uint8_t decoded_msg[decoded_msg_len];
    memcpy(decoded_msg, decoded_msg2, decoded_msg_len);
    uint8_t plain_msg[decoded_msg_len];
    string plain_str(decoded_msg_len, 0);
    uint8_t iv[iv_len];
    memcpy(iv, iv2, iv_len);
    uint8_t suffix[suffix_len];
    memcpy(suffix, suffix2, suffix_len);

    uint8_t key[32];
    make_key(suffix, suffix_len, key, thread, start);
    int bytes_needed = 32 - suffix_len;

    regex reg("^[a-zA-Zπ•Ê∆Í ≥£Ò—Û”úåüèøØ \n0-9.,!\"#%&'()*+_:;<=>?-{}]+\\0+$", std::regex::optimize);

    int loop = 0;
    long loops = 0;

    while(true){
        if(thread == 0){
            if(loop == 1111111){
                loops += loop;
                loop = 0;
                cout << loops << endl;
            }
            loop++;
        }

        uint8_t tmp_iv[iv_len];
        memcpy(tmp_iv, iv, iv_len);

        AES_KEY dec_key;
        AES_set_decrypt_key(key, 256, &dec_key);
        AES_cbc_encrypt(decoded_msg, plain_msg, decoded_msg_len, &dec_key, tmp_iv, AES_DECRYPT);
        if(remove_padding(plain_msg, decoded_msg_len)){
            utf8_to_iso_string(plain_msg, decoded_msg_len);

            smatch result;

            for(int i = 0; i < decoded_msg_len; ++i){
                plain_str[i] = plain_msg[i];
            }

            regex_match(plain_str, result, reg);
            if(!result.empty()){
                cout << "found: " << plain_msg << endl;
            }
        }

        uint8_t first_byte_before = key[0];
        increase_key(key, bytes_needed, thread, threads);
        if(first_byte_before != key[0] && key[0] == stop){
            break;
        }
    }
}

int main() {
    setlocale(LC_ALL, "");

    string cipher_text = base64_decode("KqnUmttz3a880XFATXSrYr2P0zO94ry1nsQkUkqPMYI4B+HGQdB0FEZD7FF85+eMB9Clyon8Hd3rBKHIu7hllf6uwTmQS8mDBdLhkEpbcuwvxszSQyQJyjv33MJ2jyGX7xm4/wGGvv51JayVHr3J9w==");
    vector<uint8_t> cipher_v(cipher_text.begin(), cipher_text.end());
    int cipher_len = cipher_v.size();
    uint8_t* cipher = new uint8_t[cipher_len];
    copy(cipher_v.begin(), cipher_v.end(), cipher);

    string suffix_text = "3d6c89b1349b6a9756460747ead00c4f9b8adefd9c52f27deed3fa9a36";
    int suffix_len = suffix_text.length() / 2;
    uint8_t* suffix = new uint8_t[suffix_len];
    hex2bin(suffix_text.c_str(), (char*)suffix);

    string iv_text = "46a6a02963c31381d3aac530aa3a23f5";
    int iv_len = iv_text.length() / 2;
    uint8_t* iv = new uint8_t[iv_len];
    hex2bin(iv_text.c_str(), (char*)iv);

    int threads = 8;

    thread t[threads];

    time_t t1 = time(NULL);

    for(int i = 0; i < threads; ++i){
        t[i] = std::thread(thread_decrypt, cipher, cipher_len, iv, iv_len, suffix, suffix_len, 0, 0, i, threads);
    }

    for(int i = 0; i < threads; ++i) {
        t[i].join();
    }

    cout << time(NULL) - t1 << "s" << endl;

    /*ofstream file;
    file.open("decrypted.txt", ios::out | ios::trunc);
    file << plain;
    file.close();*/

    return 0;
}