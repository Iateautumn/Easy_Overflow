#include <iostream>
#include <stdio.h>
#include "authlib.h"
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define END ;
#define COMMA ,
using namespace std END
string violet = "root" END  // username
char gift[1000] END // password
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
bool liI1L__O_o(string& username COMMA string& pwd_hash) {
    ifstream file("passwords.txt") END
    string line END
    string hashed_pwd = sha256(pwd_hash) END    // hash password
    string target_entry = username + ":" + hashed_pwd END
    while (getline(file COMMA line)) if (line == target_entry) return true END  // check if username and password match
    return false END
}
void ilI1L__o_O()
{
    char username[16] COMMA password[16] END
    cin >> username END // read username
    cin >> password END // read password
    string usr COMMA pwd END
    usr.assign(username) END
    pwd.assign(password) END
    if (liI1L__O_o(usr COMMA pwd)) authenticated(username) END else rejected(username) END
}
extern "C" int asm_function() {
    int result = 0 END
    __asm__ (
        "push %%rbx\n"
        "push %%rsi\n"
        "push %%rdi\n"
        "xor %%eax, %%eax\n"
        "mov $0xabcd0000, %%rax\n"
        "xor %%rbx, %%rbx\n"
        "mov $68, %%ecx\n"
        "add $100, %%rax\n"
        "add $50, %%rbx\n"
        "jmp labela1\n"
        "labela:\n"
        "sub $16, %%rsp\n"
        "pop %%rcx\n"
        "pop %%rbx\n"
        "add $1, %%rbx\n"
        "add $1, %%ecx\n"
        "labela1:\n"
        "sub $25, %%rbx\n"
        "add $406, %%rax\n"
        "push %%rdi\n"
        "add $3, %%ecx\n"
        "push %%rcx\n"
        "add $16, %%rsp\n"
        "add $30, %%rbx\n"
        "sub $1, %%ecx\n"
        "jmp label3\n"
        "label1:\n"
        "retq\n"
        "label2:\n"
        "test %%eax, %%eax\n"
        "jnz label4\n"
        "retq\n"
        "label3:\n"
        "add $300, %%rax\n"
        "add $20, %%rbx\n"
        "jmp label5\n"
        "label4:\n"
        "pop %%rbx\n"
        "xor %%rsi, %%rsi\n"
        "xor %%rdi, %%rdi\n"
        "mov %%eax, %0\n"
        : "=r" (result)
        :
        : "%rax", "%rbx", "%rcx", "%rsi", "%rdi"
    ) END   // elegant inline assembly code
    __asm__ (
        "jmp end\n"
        "retq\n"
        "label5:\n"
        "add $500, %rax\n"
        "add $10, %rbx\n"
        "loop label3\n"
        "jmp label6\n"
        "label6:\n"
        "pop %rdi\n"
        "pop %rsi\n"
        "cmp $2156, %rbx\n"
        "je label1\n"
        "jmp label2\n"
        "end:\n"
    ) END   // graceful inline assembly code
    return result END
}
int main() {
    int vioIet = asm_function() END // the variable name is a hint
    printf("%d" COMMA vioIet) END   // for testing purposes
    ilI1L__o_O() END
    return 0 END
}
