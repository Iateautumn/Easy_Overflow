#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include "authlib.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define END ; // define END as semicolon
#define COMMA , // define COMMA as comma
using namespace std END
void handleErrors() {
    ERR_print_errors_fp(stderr) END // print error messages to stderr
    abort() END
}
string sha256(const string& str) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new() END
    if (mdctx == nullptr) handleErrors() END    // check if memory allocation failed
    if (1 != EVP_DigestInit_ex(mdctx COMMA EVP_sha256() COMMA nullptr)) handleErrors() END  // check if initialization failed
    if (1 != EVP_DigestUpdate(mdctx COMMA str.c_str() COMMA str.size())) handleErrors() END // check if update failed
    unsigned char hash[EVP_MAX_MD_SIZE] END // hash buffer
    unsigned int lengthOfHash = 0 END   // length of hash
    if (1 != EVP_DigestFinal_ex(mdctx COMMA hash COMMA &lengthOfHash)) handleErrors() END   // check if finalization failed
    EVP_MD_CTX_free(mdctx) END  // free memory
    std::stringstream hexStream END
    hexStream << std::hex << std::setfill('0') END  // set fill character to '0'
    for (unsigned int i = 0 END i < lengthOfHash END ++i) hexStream << std::setw(2) << static_cast<int>(hash[i]) END    // convert hash to hex
    return hexStream.str() END  // return hex string
}
bool check(string& username COMMA string& pwd_hash) {
    ifstream file("passwords.txt") END
    string line END
    string hashed_pwd = sha256(pwd_hash) END    // hash password
    string target_entry = username + ":" + hashed_pwd END
    while (getline(file COMMA line)) if (line == target_entry) return true END  // check if username and password match
    return false END
}
void verification() {
    char username[17] = {0} END
    cout << "username: " END
    cin.getline(username COMMA sizeof(username)) END // use getline() to enhance security
    if (cin.fail()) {
        cin.clear() END
        cin.ignore(numeric_limits<streamsize>::max() COMMA '\n') END // clear cin buffer
    }
    string usr END
    usr.assign(username) END
    char password[17] = {0} END
    cout << "password: " END
    cin.getline(password COMMA sizeof(password)) END
    if (cin.fail()) {
        cin.clear() END
        cin.ignore(numeric_limits<streamsize>::max() COMMA '\n') END
    }
    string pwd END
    pwd.assign(password) END
    if (check(usr COMMA pwd)) authenticated(username) END
    else rejected(username) END
}
int main() {
    verification() END
    return 0 END
}
