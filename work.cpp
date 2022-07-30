#include<iostream>
#include<string>
#include<NTL/ZZ.h>
#include<time.h>
#include<vector>
#include<unordered_map>
#include <random>
NTL_CLIENT
using namespace std;
using namespace NTL;
#define ENC 0
#define DEC 1
const int SM4_S[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
        0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
        0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
        0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
        0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
        0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
        0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
        0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
        0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
        0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
        0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
        0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
        0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
        0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
        0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
        0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
        0xD7, 0xCB, 0x39, 0x48
};
const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
uint32_t cycle_leftshift(uint32_t word, int offset) {
    uint32_t temp = (word << offset);
    temp ^= (word >> (32 - offset));
    return temp;
}
void ExpandKeys(uint32_t* round_key, uint32_t* key) {
    uint32_t i, temp1, tmp;
    uint32_t temp_X[36];
    for (i = 0; i < 4; ++i) {
        temp_X[i] = key[i] ^ FK[i];
    }
    for (i = 0; i < 32; ++i) {
        tmp = CK[i] ^ temp_X[i + 1] ^ temp_X[i + 2] ^ temp_X[i + 3];
        temp1 = SM4_S[tmp & 0xFF] ^ (SM4_S[(tmp >> 8) & 0xFF] << 8) ^ (SM4_S[(tmp >> 16) & 0xFF] << 16) ^ (SM4_S[(tmp >> 24) & 0xFF] << 24);
        temp_X[i + 4] = temp_X[i] ^ temp1 ^ cycle_leftshift(temp1, 13) ^ cycle_leftshift(temp1, 23);
        round_key[i] = temp_X[i + 4];
    }
}
void Round_function(uint32_t* X, uint32_t roundKey) {
    uint32_t temp = X[1] ^ X[2] ^ X[3] ^ roundKey;
    uint32_t T_result_temp = 0;
    for (int i = 0; i < 4; i++) {
        T_result_temp = (T_result_temp << 8);
        T_result_temp ^= SM4_S[(temp >> (24 - 8 * i)) & 255];
    }
    uint32_t T_result = X[0] ^ cycle_leftshift(T_result_temp, 2) ^ cycle_leftshift(T_result_temp, 10) ^ cycle_leftshift(T_result_temp, 18) ^ cycle_leftshift(T_result_temp, 24) ^ T_result_temp;
    X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = T_result;
}
void SM4(uint32_t* plaintext, uint32_t* key, int mode) {
    uint32_t roundkey[32];
    ExpandKeys(roundkey, key);
    if (mode == ENC) {
        for (int i = 0; i < 32; i++) {
            Round_function(plaintext, roundkey[i]);
        }
    }
    else if (mode == DEC) {
        for (int i = 0; i < 32; i++) {
            Round_function(plaintext, roundkey[31 - i]);
        }
    }
}

bool GetLow1(long long Round, long long base, long long MayPrimeSub, long long MayPrime) {
    for (int i = 0; i < Round; ++i) {
        if (MayPrimeSub % MayPrime == MayPrime - 1) return true;
        MayPrimeSub = (MayPrimeSub * MayPrimeSub) % MayPrime;
    }
    return false;
}

string int2hexstr(ZZ num) {
    string re = "", get_index = "0123456789ABCDEF";;
    while (num != 0) {
        re += get_index[num % 16];
        num = num / 16;
    }
    return string(re.rbegin(), re.rend());
}

ZZ ExtEculid(ZZ a, ZZ b, ZZ& x, ZZ& y) {
    if (b == 0) {
        x = 1, y = 0;
        return a;
    }
    ZZ q = ExtEculid(b, a % b, y, x);
    y -= a / b * x;
    return q;
}

ZZ invert(ZZ a, ZZ b) {
    if (a == 0 && b == 0) {
        return (ZZ)0;
    }
    ZZ x, y;
    ZZ G = ExtEculid(a, b, x, y);
    if ((ZZ)1 % G != 0) return (ZZ)-1;
    x *= (ZZ)1 / G; y *= (ZZ)1 / G;
    b = abs(b / G);
    return (x % b + b) % b;
}

ZZ str2ZZ(string str) {
    int size = str.size();
    ZZ re = (ZZ)0;
    for (int i = 0; i < size; ++i) {
        re *= 16;
        if (str[i] >= 'A' && str[i] < 'F') {
            re += 10 + (str[i] - 'A');
        }
        else if (str[i] >= '0' && str[i] <= '9') {
            re += (str[i] - '0');
        }
    }
    return re;
}

ZZ PowMod(ZZ base, ZZ exps, ZZ mod) {
    ZZ result = (ZZ)1;
    while (exps != 0) {
        if (exps % 2 != 0)
            result = (base * result) % mod;
        base = (base * base) % mod;
        exps = (exps >> 1);
    }
    return result;
}

bool MillerRobin(long long MayPrime) {
    long long prime[9] = { 2,3,5,7,11,13,17,23,37 };
    long long base = MayPrime - 1, exps = 0;
    ZZ MayPrimeSub;
    while (base % 2 == 0 && base != 0) {
        base /= 2;
        exps++;
    }
    for (int i = 0; i < 9; ++i) {
        if (prime[i] == MayPrime) return true;
        if (MayPrime % prime[i] == 0) return false;
        MayPrimeSub = PowMod((ZZ)prime[i], (ZZ)base, (ZZ)MayPrime);
        if (MayPrimeSub != 1 && !GetLow1(exps, prime[i], to_long(MayPrimeSub), MayPrime)) return false;
    }
    return true;
}

long long factor(long long input) {
    for (long long i = 0; i < 10000000; ++i) {
        long long temp = input + i * i;
        long long sq = sqrt(temp);
        if (sq * sq == temp) {
            long long p = (sq + i);
            long long q = (sq - i);
            if (p * q == input) {
                cout << "p = " << p << "q = " << q << endl;
            }
        }
    }
    return 0;
}

class point {
public:
    ZZ x, y;
    point() {
        x = y = 0;
    }
};

class SM2parameters {
public:
    string ZA;
    point PA, G;
    ZZ M, da, n, h;
    int a, b;
    SM2parameters() {
        M = n = h = 0;
        a = b = 0;
        ZA = "";
    }
};

class SM3EncryptFunction {
private:
    string iv = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";
    uint32_t Ti[2] = { 0x79cc4519, 0x7a879d8a };
    string get_index = "0123456789ABCDEF";
    uint32_t* arr = new uint32_t[68];
    uint32_t* arr1 = new uint32_t[64];
public:
    int hex2int(char p) {                       // hex 转 int 
        return p < 58 ? p - 48 : p - 55;
    }
    uint32_t str2uint(string s) {
        uint32_t temp = 0;
        for (auto i : s)
            temp = ((temp << 4) | hex2int(i));
        return temp;
    }
    string uint2str(uint32_t num, int k = 8, string s = "") {    // unsigned int 转 string
        for (int i = 0; i < k; i++, num /= 16)
            s += get_index[num % 16];
        return string(s.rbegin(), s.rend());
    }
    uint32_t GetLeftShift(uint32_t num, int left) {             // 循环左移
        return (num << left) | (num >> (32 - left));
    }
    uint32_t GetTi(int x) {
        return x > 15 ? Ti[1] : Ti[0];
    }
    uint32_t FunctionFFi(uint32_t x, uint32_t y, uint32_t z, int n) {
        return n > 15 ? ((x & y) | (y & z) | (x & z)) : (x ^ y ^ z);
    }
    uint32_t FunctionGGi(uint32_t x, uint32_t y, uint32_t z, int n) {
        return n > 15 ? ((x & y) | ((~x) & z)) : (x ^ y ^ z);
    }
    uint32_t IntendP(uint32_t x) {
        return (x ^ GetLeftShift(x, 9) ^ GetLeftShift(x, 17));
    }
    uint32_t ExtendP(uint32_t x) {
        return (x ^ GetLeftShift(x, 15) ^ GetLeftShift(x, 23));
    }
    int AddEndOfMessage(string& s, int n, uint64_t size) {
        s.push_back('8');
        for (int i = 0; i < n / 4; i++)
            s.push_back('0');
        s += uint2str(size, 16);
        return n;
    }
    void MessageExtend(string B) {
        for (int i = 0; i < 16; i++)
            arr[i] = str2uint(B.substr(8 * i, 8));
        for (int i = 16; i < 68; i++)
            arr[i] = (ExtendP(arr[i - 16] ^ arr[i - 9] ^ GetLeftShift(arr[i - 3], 15)) ^ GetLeftShift(arr[i - 13], 7) ^ arr[i - 6]);
        for (int i = 0; i < 64; i++)
            arr1[i] = (arr[i] ^ arr[i + 4]);
    }
    string FunctionCF(string V) {
        uint32_t vi[8], vi_copy[8];
        for (int i = 0; i < 8; i++) {
            vi[i] = str2uint(V.substr(8 * i, 8));
            vi_copy[i] = vi[i];
        }
        for (int i = 0; i < 64; i++) {
            uint32_t SS1 = GetLeftShift((GetLeftShift(vi[0], 12) + vi[4] + GetLeftShift(GetTi(i), i % 32)), 7);
            uint32_t SS2 = (SS1 ^ GetLeftShift(vi[0], 12));
            uint32_t TT1 = FunctionFFi(vi[0], vi[1], vi[2], i) + vi[3] + SS2 + arr1[i];
            uint32_t TT2 = FunctionGGi(vi[4], vi[5], vi[6], i) + vi[7] + SS1 + arr[i];
            vi[3] = vi[2]; vi[2] = (GetLeftShift(vi[1], 9)); vi[1] = vi[0];
            vi[0] = TT1; vi[7] = vi[6]; vi[6] = GetLeftShift(vi[5], 19); vi[5] = vi[4]; vi[4] = IntendP(TT2);
        }
        string result = "";
        for (int i = 0; i < 8; i++)
            result += uint2str(vi_copy[i] ^ vi[i]);
        return result;
    }
public:
    string SM3Encrypt(string m) {
        uint64_t size = (uint64_t)m.size() * (uint64_t)4;
        uint64_t num = (size + 1) % 512;
        int k = AddEndOfMessage(m, num < 448 ? 448 - num : 960 - num, size);
        uint64_t group_number = (size + 65 + k) / 512;
        string* B = new string[group_number];
        string* V = new string[group_number + 1];
        V[0] = iv;
        for (int i = 0; i < group_number; i++) {
            B[i] = m.substr(128 * i, 128);
            MessageExtend(B[i]);
            V[i + 1] = FunctionCF(V[i]);
        }
        return V[group_number];
    }
};

SM3EncryptFunction SM3Test;  // 输入是16进制字符串

class SM3Attack :public SM3EncryptFunction {
public:
    string output;
    string input;
    char seed[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
    SM3Attack(string salt, string message) {
        this->input = salt + message;
        this->output = SM3Test.SM3Encrypt(input);
    }

    bool lengthAttack() {
        string lengthExtend, temp;
        string outputTemp = output;
        do {
            lengthExtend = to_string(rand());
            outputTemp += lengthExtend;
            temp = SM3Test.SM3Encrypt(outputTemp);
            if (temp == output) return true;
        } while (true);

    }


    string getInput() {
        static std::random_device rd; 
        static std::mt19937 gen(rd()); 
        static std::uniform_int_distribution<> dis(0, 16);
        string input = "";
        for (int n = 0; n < 100; n++) {
            int val = dis(gen);
            input += seed[val];
        }
        return input;
    }

    void birthdayAttack() {
        unordered_map<string, string>table;
        ZZ input;
        while (true) {
            RandomLen(input, 128);
            string temp = int2hexstr(input);
            string output = SM3Test.SM3Encrypt(temp);
            if (table.count(output)) {
                cout << "true" << endl;
                break;
            }
            table.insert({ output,temp });
        }
    }

    auto rhoAttack(int n) {
        int size = n / 4, i = 1;
        string input = getInput(), fpointer, rpointer;
        do {
            fpointer = SM3Test.SM3Encrypt(SM3Test.SM3Encrypt(fpointer));
            rpointer = SM3Test.SM3Encrypt(rpointer);
            i++;
        }while (fpointer.substr(0, size) != rpointer.substr(0, size));
        fpointer = SM3Test.SM3Encrypt(input);
        rpointer = SM3Test.SM3Encrypt(input);
        for (int j = 0; j < i; j++) fpointer = SM3Test.SM3Encrypt(fpointer);
        for (int j = 0; j <= i; j++) {
            string temp1 = SM3Test.SM3Encrypt(rpointer);
            string temp2 = SM3Test.SM3Encrypt(fpointer);
            if (temp2.substr(0, size) == temp1.substr(0, size)) {
                cout << "true" << endl; 
                return make_tuple(rpointer, fpointer);
            }
            else {
                rpointer = temp1;
                fpointer = temp2;
            }
        }
    }

};

class TreeNode {
public:
    TreeNode* leftChild, * rightChild, * brother, * parent;
    string val;
public:
    TreeNode() :val(""), leftChild(nullptr), rightChild(nullptr), brother(nullptr), parent(nullptr) {}
    TreeNode(string val) :val(val), leftChild(nullptr), rightChild(nullptr), brother(nullptr), parent(nullptr) {}
};

class MerkleTree {
public:
    vector<TreeNode*>MerkleTreeLeafHashNum;
    vector<TreeNode*>MerkleTreeLeafHashTemp;
    unordered_map<string, TreeNode*>table;
    string hashHead;
    int count;
protected:
public:
    MerkleTree(int num) {
        count = num;
        hashHead = "";
        for (int i = 0; i < num; ++i) {
            TreeNode* temp = new TreeNode(SM3Test.SM3Encrypt(to_string(i)));
            MerkleTreeLeafHashNum.push_back(temp);
            table.insert({ to_string(i),temp });
        }
    }

    void MerkleTreeCreate() {
        while (count > 1) {
            for (int i = 0; i < count - 1; i += 2) {
                TreeNode* temp = new TreeNode(SM3Test.SM3Encrypt(MerkleTreeLeafHashNum[i]->val + MerkleTreeLeafHashNum[i + 1]->val));
                temp->leftChild = MerkleTreeLeafHashNum[i];
                temp->rightChild = MerkleTreeLeafHashNum[i + 1];
                MerkleTreeLeafHashNum[i]->brother = MerkleTreeLeafHashNum[i + 1];
                MerkleTreeLeafHashNum[i + 1]->brother = MerkleTreeLeafHashNum[i];
                MerkleTreeLeafHashNum[i]->parent = temp;
                MerkleTreeLeafHashNum[i + 1]->parent = temp;
                MerkleTreeLeafHashTemp.push_back(temp);
            }
            if (count & 1)
                MerkleTreeLeafHashTemp.push_back(MerkleTreeLeafHashNum[count++ - 1]);

            count /= 2;

            MerkleTreeLeafHashNum = MerkleTreeLeafHashTemp;
            MerkleTreeLeafHashTemp.clear();
        }
        hashHead = MerkleTreeLeafHashNum[0]->val;
    }

    bool MerkleTreeCheck(string hashNum) {
        if (!table.count(hashNum)) return 0;
        TreeNode* head = table[hashNum];
        string result = head->val;
        while (head->parent) {
            if (head->brother != nullptr)
                result = SM3Test.SM3Encrypt(result + head->brother->val);
            head = head->parent;
        }
        return hashHead == head->val;
    }



};

point doublePoint(point p, int a, ZZ Mod, point result) {
    if (p.x == 0) {
        p.y = 0; return p;
    }
    ZZ lambda = (Mod + (3 * p.x * p.x+ a) * (invert((ZZ)2 * p.y % Mod, Mod)+Mod) % Mod) % Mod;
    result.x = ((lambda * lambda - p.x - p.x) + 2 * Mod) % Mod;
    result.y = ((lambda * (p.x - result.x) - p.y) % Mod + 300*Mod) % Mod;
    return result;
}

point addPoint(point p1, point p2, int a, ZZ Mod, point result) {
    if (p1.x == 0) return p2;
    if (p2.x == 0) return p1;
    if (p1.x == p2.x) {
        if (p1.y != p2.y) return result;
        else return doublePoint(p1, a, Mod, result);
    }
    else{
        ZZ lambda = (Mod + (p2.y - p1.y + Mod) * invert(p2.x - p1.x + Mod, Mod) % Mod) % Mod;
        result.x = ((lambda * lambda - p1.x - p2.x)  + 100*Mod) % Mod;
        result.y = ((lambda * (p1.x - result.x) - p1.y) + 100*Mod) % Mod;
    }
    return result;
}

point mulPoint(point p, ZZ mul, int a, ZZ Mod) {
    point result;
    point re;
    while (mul > 0) {
        if (mul % 2) re = addPoint(re, p, a, Mod, result);
        p = doublePoint(p, a, Mod, result);
        mul /= 2;
    }
    return re;
}

void SM2Init(SM2parameters& param) {
    param.n = 11;
    param.M = param.h = 12;
    param.a = 0, param.b = 7;
    param.ZA = "";
    param.G.x = 7;
    param.G.y = 8;
    param.da = 4;
    param.PA = mulPoint(param.G, param.da, param.a, param.n);
}

int getLength(int num) {
    int t = 0;
    while (num != 0) {
        num = (num >> 1);
        t++;
    }
    return t;
}



string preComputZa(int ID, int IDlength, int a, int b, point p, point pa) {
    string input = "";
    input += int2hexstr((ZZ)IDlength) + int2hexstr((ZZ)ID) + int2hexstr((ZZ)a) + int2hexstr((ZZ)b) + int2hexstr(p.x) + int2hexstr(p.y) + int2hexstr(pa.x) + int2hexstr(pa.y);
    string Za = SM3Test.SM3Encrypt(input);
    return Za;
}
ZZ kForThink;

void SM2Sign(SM2parameters& param, ZZ sk, int ID, string M, ZZ& rp, ZZ& sp) {
    int IDlength = getLength(ID);
    point p, p1;
    param.ZA = preComputZa(ID, IDlength, param.a, param.b, p, p1);
    string e = SM3Test.SM3Encrypt(param.ZA + M);
    ZZ ep = str2ZZ(e);
    do {
        ZZ k;
        RandomLen(k, 128);
        k %= (ZZ)param.h;
        //cout << "k=" << k << endl;
        point re = mulPoint(param.G, k, param.a, param.n);
        //cout << "sign re.x="<<re.x << endl;
        ZZ r = (ZZ)((ep + re.x) % param.n);
        if (r == 0 || r + k == param.h) continue;
        ZZ s = (ZZ)(invert(1 + param.da, param.h) * (k - r * param.da) % param.h);
        if (s != 0) {
            rp = r;
            sp = s;
            kForThink = k;
            //cout << "re.kg : " << re.x << " " << re.y << endl;
            break;
        }
    } while (1);
}

int SM2Verify(SM2parameters& param, ZZ r, ZZ s, string M) {
    if (r<1 || r>param.h - 1) return 0;
    if (s<1 || s>param.h - 1) return 0;
    string Mnot = param.ZA + M;
    string e = SM3Test.SM3Encrypt(Mnot);
    ZZ ep = str2ZZ(e);
    ZZ t = (ZZ)((r + s) % param.h);
    //cout << "t=" << t << endl;
    //cout << "s=" << s << endl;
    
    if (t == 0) return -1;
    point temp;
    point re = mulPoint(param.G,s,param.a,param.n);
    //cout << "re=" << re.x<<endl;
    //cout << "mul = " << mulPoint(param.PA, t, param.a, param.n).x << endl;
    re = addPoint(re, mulPoint(param.PA, t, param.a, param.n), param.a, param.n, temp);
    //cout << "re=" << re.x << endl;
    ZZ R = (ZZ)((ep + re.x) % param.n);
    return R == r ? 1 : 0;
}

ZZ gcd(ZZ m, ZZ n)
{
    ZZ t;
    while (n != 0) {
        t = m % n;
        m = n;
        n = t;
    }
    return m;
}

struct sign2p {
    ZZ r, s;
    sign2p() { r = s = 0; }
};

sign2p SM2_2pSign(SM2parameters& param, string M) {
    ZZ d1, k1, d2;

    do {
        RandomLen(d1, 128);
        d1 %= (ZZ)param.h;
        RandomLen(d2, 128);
        d2 %= (ZZ)param.h;
        if (gcd(d1, param.h) == 1 && gcd(d2, param.h) == 1)break;
    } while (1);
    ZZ mul1 = (ZZ)invert(d1, param.h);
    point P1 = mulPoint(param.G, mul1, param.a, param.n);

    RandomLen(k1, 128);
    k1 %= (ZZ)param.h;
    point Q1 = mulPoint(param.G, k1, param.a, param.n);

    string Mnot = param.ZA + M;
    string e = SM3Test.SM3Encrypt(Mnot);

    ZZ k2, k3;
    RandomLen(k2, 128);
    RandomLen(k3, 128);
    k2 %= (ZZ)param.h;
    k3 %= (ZZ)param.h;
    ZZ mul2 = (ZZ)invert(d2, param.h);

    point P2 = mulPoint(P1, mul2, param.a, param.n), temp;
    point GTemp = param.G;
    GTemp.y = param.n - param.G.y;
    P2 = addPoint(P2, GTemp, param.a, param.n, temp);
    point Q2 = mulPoint(param.G, k2, param.a, param.n);
    point Q3 = mulPoint(Q1, k3, param.a, param.n);
    Q3 = addPoint(Q3, Q2, param.a, param.n, temp);
    ZZ ep = str2ZZ(e);
    ZZ r = (ZZ)((Q3.x + ep) % param.n);
    ZZ s2 = (d2 * k3) % param.h;
    ZZ s3 = d2 * (r + k2) % param.h;

    ZZ s = ((d1 * k1) * s2 + d1 * s3 - r) % param.h;
    sign2p result;
    //cout << r << endl;
    //cout << s << endl;
    if (s == 0 || s == param.h - r) return result;
    cout << "success" << endl;
    result.r = r;
    result.s = s;
    return result;
}

struct Enc2p {
    point c1;
    ZZ c2;
    string c3;
    Enc2p() { c2 = 0; c3 = ""; }
};

void SM2EncOnly(string M, SM2parameters& param, point pk, Enc2p& result) {
    ZZ k;
    RandomLen(k, 128);
    k %= param.h;
    point c1 = mulPoint(param.G, k, param.a, param.n);
    point s = mulPoint(pk, (ZZ)5, param.a, param.n);
    point kpb = mulPoint(pk, k, param.a, param.n);
    string t = SM3Test.SM3Encrypt(int2hexstr(kpb.x) + int2hexstr(kpb.y));
    ZZ c2 = str2ZZ(M) ^ str2ZZ(t);
    //cout << str2ZZ(M) << endl;
    string c3 = SM3Test.SM3Encrypt(int2hexstr(kpb.x) + M + int2hexstr(kpb.y));
    result.c1 = c1, result.c2 = c2, result.c3 = c3;
}

void SM2DecOnly(SM2parameters& param, ZZ sk, Enc2p result, ZZ& M) {
    // 判断c1满足曲线方程
    point s = mulPoint(result.c1, (ZZ)5, param.a, param.n);
    point reTemp = mulPoint(result.c1, sk, param.a, param.n);
    string t = SM3Test.SM3Encrypt(int2hexstr(reTemp.x) + int2hexstr(reTemp.y));
    ZZ Mnot = result.c2 ^ str2ZZ(t);
    string u = SM3Test.SM3Encrypt(int2hexstr(reTemp.x) + int2hexstr(Mnot) + int2hexstr(reTemp.y));
    //cout << u << "\n" << result.c3 << endl;
    if (u == result.c3) { M = Mnot; cout << "success" << endl; }
    
}


void SM2Dec2p(SM2parameters& param, string M, Enc2p& result) {
    ZZ k, d1, d2;
    RandomLen(k, 128);
    k %= (ZZ)param.h;
    do {
        
        RandomLen(d1, 128);
        RandomLen(d2, 128);
        
        d1 %= (ZZ)param.h;
        d2 %= (ZZ)param.h;
        if (gcd(d1, param.h) == 1 && gcd(d2, param.h) == 1)
            break;
    } while (1);
    point c1 = mulPoint(param.G, k, param.a, param.n);

    point P = mulPoint(param.G, invert(d1 * d2, param.h) - 1, param.a, param.n);
    point PointTemp = mulPoint(P, k, param.a, param.n);
    string t = SM3Test.SM3Encrypt(int2hexstr(PointTemp.x)+int2hexstr(PointTemp.y));

    ZZ c2 = str2ZZ(M) ^ str2ZZ(t);
    string c3 = SM3Test.SM3Encrypt(int2hexstr(PointTemp.x) + M + int2hexstr(PointTemp.y));
    
    point T1 = mulPoint(c1, invert(d1, param.h), param.a, param.n);
    point T2 = mulPoint(T1, invert(d2, param.h), param.a, param.n);
    point c1Temp = c1, re;
    if (c1.y == 0) cout << "repeat" << endl;
    c1Temp.y = param.n - c1.y;
    point T3 = addPoint(T2, c1Temp, param.a, param.n, re); 
    string ts = SM3Test.SM3Encrypt(int2hexstr(T3.x) + int2hexstr(T3.y));


    ZZ Ms = c2 ^ str2ZZ(ts);
    string u = SM3Test.SM3Encrypt(int2hexstr(T3.x) + int2hexstr(Ms) + int2hexstr(T3.y));
    //cout << u << "\n" << c3 << endl;

    if (u == c3) cout << "true" << endl;
}

void PGPEnc(SM2parameters& param, Enc2p& result, uint32_t* M, uint32_t* key, point pk) {
    SM4(M, key, ENC);
    string Mstr = "";
    for (int i = 0; i < 4; ++i) Mstr += int2hexstr((ZZ)key[i]);
    SM2EncOnly(Mstr, param, pk, result);
}

void PGPDec(SM2parameters& param, uint32_t* cipher, ZZ sk, Enc2p result) {
    ZZ M;
    SM2DecOnly(param, sk, result, M);
    uint32_t key[4];
    for (int i = 0; i < 4; ++i) {
        key[3 - i] = to_uint(( M >> (32 * i)) & UINT32_MAX);
       // cout << hex << key[3 - i] << " ";
    }
    SM4(cipher, key, DEC);
}

int circuit425(int score) {
    if (score >= 750 || score <= 0) return -1;
    int standard = 425;
    int lowPut = 0;
    for (int i = 0; i < 10; ++i) {
        int lowBit = standard & 1;
        int lowBitScore = score & 1;
        standard = (standard >> 1);
        score = (score >> 1);
        lowPut = (lowBitScore ^ ((lowBit ^ lowPut) & (lowBitScore ^ lowPut)));
    }
    /*
    string str = "";
    if (SM3Test.SM3Encrypt(to_string(score)) != str)return 0;
    // str 是教育部的那个哈希值
    */
    return lowPut;
}

sign2p forge(SM2parameters& param, point pk, ZZ& e) {
    ZZ u, v;
    RandomLen(u, 128);
    RandomLen(v, 128);
    u %= param.h;
    v %= param.h;
    point result;
    point uG = mulPoint(param.G, u, param.a, param.n);
    point vp = mulPoint(pk, v, param.a, param.n);
    point R = addPoint(uG, vp, param.a, param.n, result);
    ZZ r = vp.x;
    ZZ enot = r * u * invert(v, param.n) % param.n;
    ZZ s = r * invert(v, param.n) % param.n;
    sign2p re;
    re.r = r;
    re.s = s;
    e = enot;
    return re;
}

point ECMH(SM2parameters& param, string tx) {
    string t = SM3Test.SM3Encrypt(tx);
    ZZ tp = str2ZZ(t);
    ZZ re = (ZZ)0;
    do {
        re = PowMod(tp, (param.n - 1) / 2, param.n);
        if (re == 1) break;
        t = SM3Test.SM3Encrypt(t);
        tp = str2ZZ(t);
    } while (1);
    point result;
    result.x = tp;
    result.y = PowMod(re, (param.n + 1) / 4, param.n);
    return result;
}

point pkThink(SM2parameters& param, sign2p signature, string M) {
    point p1;
    string e = SM3Test.SM3Encrypt(param.ZA + M);
    ZZ ep = str2ZZ(e);
    p1.x = (signature.r - ep) % param.n;
    ZZ NumTemp = (ZZ)(p1.x * p1.x * p1.x + param.a * p1.x + param.b) % param.n;
    for (int i = 0; i < param.n; ++i) {
        if ((ZZ)(i * i) % param.n == NumTemp) {
            p1.y = (ZZ)i;
            break;
        }
    }
    //cout << p1.x << " tt " << p1.y << endl;
    point p2 = mulPoint(param.G, signature.s, param.a, param.n);
    ZZ inv = invert((signature.s + signature.r), param.n);
    p2.y = param.n - p2.y;
    //cout << p2.x << " " << p2.y << endl;
    point re;
    point temp = addPoint(p1, p2, param.a, param.n, re);
    point pk = mulPoint(temp, inv, param.a, param.n);
    return pk;
}

void SM2SignSameK(SM2parameters& param, ZZ sk, int ID, string M, ZZ& rp, ZZ& sp) {
    int IDlength = getLength(ID);
    point p, p1;
    param.ZA = preComputZa(ID, IDlength, param.a, param.b, p, p1);
    string e = SM3Test.SM3Encrypt(param.ZA + M);
    ZZ ep = str2ZZ(e);
    do {
        ZZ k;
        RandomLen(k, 128);
        k %= (ZZ)param.h;
        k = 5;
        //cout << "k=" << k << endl;
        point re = mulPoint(param.G, k, param.a, param.n);
        //cout << "sign re.x="<<re.x << endl;
        ZZ r = (ZZ)((ep + re.x) % param.h);
        if (r == 0 || r + k == param.h) continue;
        ZZ s = (ZZ)(invert(1 + param.da, param.h) * (k - r * param.da) % param.h);
        if (s != 0) {
            rp = r;
            sp = s;
            kForThink = k;
            //cout << "re.kg : " << re.x << " " << re.y << endl;
            break;
        }
    } while (1);
}

point RFC6979(SM2parameters& param, sign2p A, sign2p B, ZZ same_k) {
    ZZ db = (same_k - B.s) * invert(B.s + B.r, param.h) % param.h;
    ZZ da = (same_k - A.s) * invert(A.s + A.r, param.h) % param.h;
    point re;
    re.x = da, re.y = db;
    return re;
}

struct blockData {
    int version;
    string frontHash;
    string rootHash;
    int time;
    int target;
    int nonce;
};

uint32_t str2uint32_t(string s, int first, int length) {
    uint32_t temp = 0;
    for (int i = first; i < first + length; ++i)
        temp = ((temp << 4) | (s[i] < 58 ? s[i] - 48 : s[i] - 55));
    return temp;
}

blockData praseHead(string tx) {
    blockData re;
    re.version = str2uint32_t(tx, 0, 8);
    re.frontHash = re.rootHash = "";
    for (int i = 8; i < 72; ++i)
        re.frontHash += tx[i];
    for (int i = 72; i < 136; ++i)
        re.rootHash += tx[i];
    re.time = str2uint32_t(tx, 136, 8);
    re.target = str2uint32_t(tx, 144, 8);
    re.nonce = str2uint32_t(tx, 152, 8);
    return re;
}

unordered_map<string, vector<string>> map;
void GooglePush(ZZ sk, ZZ p) {
    string user = "12", password = "12"; // 16进制
    // cin >> user >> password;
    string input = user + password;
    string h = SM3Test.SM3Encrypt(input);
    string ki = "" + h[0] + h[1] + h[2] + h[3];
    ZZ vi = PowMod(str2ZZ(h), sk, p);
    if (!map.count(ki)) {
        vector<string> str;
        str.push_back(int2hexstr(vi));
        map.insert({ ki, str });
    }else
        map[ki].push_back(int2hexstr(vi));
}

void client(ZZ p, string& ki, ZZ& vi, ZZ& clientsk) {
    string user = "12", password = "12"; // 16进制
    // cin >> user >> password;
    ZZ sk;
    do {
        RandomLen(sk, 128);
        sk %= p;
    } while (gcd(sk, p - 1) != 1);
    clientsk = sk;
    string input = user + password;
    string h = SM3Test.SM3Encrypt(input);
    ki = "" + h[0] + h[1] + h[2] + h[3];
    vi = PowMod(str2ZZ(h), sk, p);
}

void server(ZZ& vi, string ki, ZZ sk, ZZ p, vector<string>& S) {
    ZZ vh = PowMod(vi, sk, p);
    if (!map.count(ki)) {
        cout << "wrong" << endl;
        return;
    }
    S = map[ki];
    vi = vh;
}

void clientCheck(vector<string> S, ZZ vi, ZZ p, ZZ sk) {
    ZZ inv = invert(sk, p - 1) % (p - 1);
    ZZ hb = PowMod(vi, inv, p);
    for (auto i : S) {
        if (i == int2hexstr(hb)) {
            cout << "true" << endl; 
            return;
        }
    }
    cout << "404 not Found" << endl;
}

void shift(ZZ s[]) {
    ZZ temp = s[7];
    for (int i = 7; i > 0; --i) {
        s[i] = s[i - 1];
    }
    s[0] = temp;
}

ZZ AESinv(ZZ input) {
    return (ZZ)0;
}

void pop(string M) {
    ZZ MAX128 = (ZZ)1, s[8];
    MAX128 = (MAX128 << 128);
    s[0] = str2ZZ(M);
    for (int i = 1; i < 8; ++i) s[i] = 0; // 结果全0时，squeeze就没用了
    for (int i = 0; i < 12; ++i) {
        shift(s);
        s[1] ^= s[2]; s[4] ^= s[1];
        s[5] = (s[5] - s[6]) % MAX128;
        s[4] = AESinv(s[4]); s[4] ^= s[6];
        s[1] = (s[1] - s[5]) % MAX128;
        s[0] ^= s[4]; s[0] = AESinv(s[0]);
    }
    string re = "";
    for (int i = 0; i < 2; ++i) {
        shift(s);
        ZZ message;
        RandomLen(message, 256);
        string messagestr = int2hexstr(message);
        ZZ str10 = (message & (MAX128 - 1));
        ZZ str00 = ((message >> 128) & (MAX128 - 1));
        ZZ str0f = ((message >> 8) & (MAX128 - 1));
        ZZ str01 = ((message >> 120) & (MAX128 - 1));
        s[1] ^= str10;
        s[2] = (s[2] - str01) % MAX128;
        s[4] ^= s[1]; s[4] = AESinv(s[4]);
        s[4] ^= str00;
        s[6] = (s[6] - str0f) % MAX128;
        s[0] ^= s[4]; s[0] = AESinv(s[0]);
        re += messagestr;
    }
    cout << re << endl;
    for (int i = 0; i < 8; ++i) cout << s[i] << " ";
}

int main() {
    SM2parameters param;
    SM2Init(param);

    ZZ ta, tb;
    /*for (int i = 0; i < 10; ++i) {
        SM2Sign(param, param.da, 2, "EA", ta, tb);
        cout << SM2Verify(param, ta, tb, "EA")<<endl;
    }*/
     
    //for (int i = 0; i < 5; ++i)
        //SM2_2pSign(param, "EA");

    
    /*cout << SM3Test.SM3Encrypt("EA") << endl;
    time_t t1 = clock();
    for (int i = 0; i < 1000; ++i) {
        SM3Test.SM3Encrypt("EA");
    }
    time_t t2 = clock();
    cout << "hash1000次，总共用时" << t2 - t1 << "ms，平均每次" << (double)(t2 - t1) / 1000 << "ms" << endl;
    */


    Enc2p enc;
    ZZ result;
    /*for (int i = 0; i < 10; ++i) {
        SM2EncOnly("EA", param, param.PA, enc);
        SM2DecOnly(param, param.da, enc, result);
        //cout << hex << result << endl;
    }*/

    //SM2Dec2p(param, "EA", enc);

    uint32_t arr[4] = { 0x01234567,0x09ABCDEF,0x0EDCBA98,0x76543210 };
    uint32_t key[4] = { 0x01234567,0x09ABCDEF,0x0EDCBA98,0x76543210 };
    //PGPEnc(param, enc, arr, key, 4, param.PA);
    //PGPDec(param, arr, param.da, enc);
    point p,te;
    
    /*MerkleTree Tree(100000);
    Tree.MerkleTreeCreate();
    cout << Tree.MerkleTreeCheck("800") << endl;
    cout << Tree.MerkleTreeCheck("100002") << endl;*/

    for (int i = 0; i < 15; ++i) { 
        p = addPoint(param.G, p, param.a, param.n, te);
        //cout << p.x << " " << p.y << endl;
    }
    
    /*cout << circuit425(400) << endl;
    cout << circuit425(450) << endl;*/

    /*SM2Sign(param, param.da, 2, "EA", ta, tb);
    sign2p sig;
    sig.r = ta;
    sig.s = tb;
    point ptemp = pkThink(param, sig, "EA");
    cout << "可能的公钥1：" << ptemp.x << " " << ptemp.y << endl;
    cout << "可能的公钥2：" << ptemp.x << " " << param.n - ptemp.y << endl;
    cout << "公钥：" << param.PA.x << " " << param.PA.y << endl;*/

    /*ZZ eIn;
    sign2p sigForge = forge(param, param.PA, eIn);
    cout << sigForge.r << " " << sigForge.s << " " << eIn << endl;*/

    //SM3Attack att("123", "123") ;
    //att.birthdayAttack();
    //att.rhoAttack(10);
    //cout << att.lengthAttack() << endl;

    /*sign2p sig1, sig2;
    SM2SignSameK(param, param.da, 2, "E3", ta, tb);
    sig1.r = ta, sig1.s = tb;
    SM2SignSameK(param, param.da, 3, "FD", ta, tb);
    sig2.r = ta, sig2.s = tb;
    point re = RFC6979(param, sig1, sig2, kForThink);
    cout << "私钥1和私钥2：" << re.x << " " << re.y << endl;
    cout << "真正的私钥：" << param.da << endl;*/

    //cout << SM3Test.SM3Encrypt("616263") << endl;

    /*string ki;
    ZZ vi, clientsk;
    vector<string>S;
    for (int i = 0; i < 10; ++i) {
        cout << i + 1 << " ";
        GooglePush((ZZ)29, (ZZ)71);
        client((ZZ)71, ki, vi, clientsk);
        server(vi, ki, (ZZ)29, (ZZ)71, S);
        clientCheck(S, vi, (ZZ)71, clientsk);
    }*/
}