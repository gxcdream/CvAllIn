#include "encrypt/encrypt.h"

enum {encrypt,decrypt}; //ENCRYPT:加密，DECRYPT：解密  
static void des_run(BYTE out[8], BYTE in[8],bool type=encrypt);
//设置密钥  
static void des_setkey(const unsigned char key[8]);  
//static void f_func(bool in[32],const bool ki[48]);//f函数  
static void f_func(bool sp_out[32], bool in[32],const bool ki[48]);//f函数  
static void s_func(bool *out,const bool in[48]);//s盒代替  
//变换  
static void transform(bool *out, bool *in, const unsigned char *table, int len);  
static void xor(bool *ina, const bool *inb, int len);//异或  
static void rotatel(bool *in, int len, int loop);//循环左移  
//字节组转换成位组  
static void byte2bit(bool *out,const unsigned char *in, int bits);
// s盒置换，byte->bit
static void byte2bitsBox(bool *out,const unsigned char *in,int bits);
//位组转换成字节组  
static void bit2byte(BYTE *out, const bool *in, int bits);
static void bits2Hex(unsigned char *dstHex, bool* srcBits, unsigned int sizeBits);

/*Table*/
//初始置换IP表  
const static unsigned char ip_table[64]=
{
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
//逆置换IP-1表  
const static unsigned char ipr_table[64]=
{
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};
//E 位选择表  
static const unsigned char e_table[48]=
{
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};  

//P换位表  // 32-bit permutation function P used on the output of the S-boxes 
const static unsigned char p_table[32]=
{
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};  
//pc1选位表  
const static unsigned char pc1_table[56]={  
    57,49,41,33,25,17,9,1,  
    58,50,42,34,26,18,10,2,  
    59,51,43,35,27,19,11,3,  
    60,52,44,36,63,55,47,39,  
    31,23,15,7,62,54,46,38,  
    30,22,14,6,61,53,45,37,  
    29,21,13,5,28,20,12,4  
};  
//pc2选位表  
const static unsigned char pc2_table[48]={  
    14,17,11,24,1,5,3,28,  
    15,6,21,10,23,19,12,4,  
    26,8,16,7,27,20,13,2,  
    41,52,31,37,47,55,30,40,  
    51,45,33,47,44,49,39,56,        // @right->51,45,33,[48],44,49,39,56,  
    34,53,46,42,50,36,29,32  
};  
//左移位数表  
const static unsigned char loop_table[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};  
//S盒  
const static BYTE s_box[8][4][16]={  
    //s0  
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,  
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,  
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,  
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,  
    //s1  
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,  
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,  
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,  
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,  
    //s2  
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,  
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,  
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,  
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,  
    //s3  
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,  
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,  
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,  
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,  
    //s4  
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,  
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,  
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,  
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,  
    //s5  
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,  
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,  
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,  
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,  
    //s6  
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,  
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,  
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,  
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,  
    //s7  
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,  
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,  
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,  
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11  
};  
static bool subkey[16][48];//16圈子密钥 
bool s_out[32];          //S盒代替运算结果

void printHexByBits(bool *in_bool, unsigned int size)
{
    unsigned char hex[16];
    bits2Hex(hex, in_bool, size);
    for (int ii=0; ii<(size/4); ++ii)
    {
        cout << hex[ii];
    }
    cout << endl;
}

void printHexByByte(BYTE *in, unsigned int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("%x ", in[i]);
    } 
    cout << endl;
}

void printBool(const bool *in, unsigned int size)
{
    for (int ii=0; ii<size; ++ii)
    {
        cout << in[ii];
    }
    cout << endl;
}
// bit 转hex
void bits2Hex(unsigned char *dstHex, bool* srcBits, unsigned int sizeBits)
{
    memset(dstHex,0,sizeBits>>2);
    for(unsigned int i=0; i < sizeBits; i++) //convert to int 0-15
        dstHex[i>>2] += (srcBits[i] << (3 - (i & 3)));
    for(unsigned int j=0;j < (sizeBits>>2);j++)
        dstHex[j] += dstHex[j] > 9 ? 55 : 48; //convert to char '0'-'F'
}

void des_run(BYTE out[8], BYTE in[8], bool type)
{  
    static bool m[64],tmp[32],*li=&m[0], *ri=&m[32];  
    byte2bit(m,in,64);
    //初始置换IP表，只处理一次
    transform(m,m,ip_table,64);
    static bool sp_out[32];
    if(type==encrypt){  
        for(int i=0;i<16;i++){  
            memcpy(tmp,ri,32);
            // 扩展置换后、R0与子密钥异或、S盒代替
            f_func(sp_out, ri,subkey[i]);  
            // sp_out与 L 异或 →xor_2
            xor(sp_out,li,32);
            // data左右调换
            memcpy(li,tmp,32);
            memcpy(ri,sp_out,32);
        }  
    }else{  
        for(int i=15;i>=0;i--){
            // 解密所用算法与加密相同，只需逆序使用subkey即可
            memcpy(tmp,ri,32);  
            f_func(sp_out, ri,subkey[i]);
            xor(sp_out,li,32);
            memcpy(li,tmp,32);
            memcpy(ri,sp_out,32);
        }  
    }

    // 最后一轮不做左右调换（进行一次逆调换）
    memcpy(tmp,li,32);
    memcpy(li,ri,32);
    memcpy(ri,tmp,32);
    // 末尾IP-1置换
    transform(m,m,ipr_table,64);
    bit2byte(out,m,64);
}

void des_setkey(const unsigned char key[8])  
{  
    static bool k[64], *kl=&k[0], *kr=&k[28];

    byte2bit(k,key,64);
    transform(k,k,pc1_table,56);
    for(int i=0;i<16;i++)  
    {  
        rotatel(kl,28,loop_table[i]);  
        rotatel(kr,28,loop_table[i]);  
        transform(subkey[i],k,pc2_table,48);
    }  
}  
void f_func(bool sp_out[32], bool in[32],const bool ki[48])  
{  
    static bool mr[48];  
    // ### 扩展置换 ok###
    transform(mr,in,e_table,48);

    // ### 异或 ok###
    xor(mr,ki,48);

    // ### S盒代替 ###
    s_func(sp_out, mr);           
    // ### S盒代替之后，P盒置换 ###
    transform(sp_out,sp_out,p_table,32);
}  

void s_func(bool *sp_out,const bool in[48])  
{  
    bool s4[4];

    for(char i=0,j,k;i<8;i++,in+=6,sp_out+=4)  
    {     
        // @right =>
        /*j=(in[0]<<1)+in[5];  
        k=(in[1]<<3)+(in[2]<<2)+(in[3]<<1)+in[4];*/

        // wrong but now in use =>
        j=(in[0]<<1)+(in[5]);                                       // row id
        k=(in[4]<<3)+(in[3]<<2)+(in[2]<<1)+in[1];     // col id
        byte2bitsBox(s4,&s_box[i][j][k],4);
        memcpy(sp_out, s4, 4);
    }
}  

void transform(bool *out,bool *in,const unsigned char *table,int len)  
{  
    bool tmp[256];  
    for(int i=0;i<len;i++)  
        tmp[i]=in[table[i]-1];  
    memcpy(out,tmp,len);  
}  
void xor(bool *ina,const bool *inb,int len)  
{  
    for(int i=0;i<len;i++)  
        ina[i]^=inb[i];  
}  
void rotatel(bool *in,int len,int loop)  
{  
    bool tmp[256];  
    memcpy(tmp,in,loop);  
    memcpy(in,in+loop,len-loop);  
    memcpy(in+len-loop,tmp,loop);  
}  
void byte2bit(bool *out, const unsigned char *in,int bits)  
{  
    for(int i=0;i<bits;i++)  
    {
        out[i]=(in[i/8]>>(7-(i%8))) &1;     // @注意高低位顺序，(7-(i%8))
    }
} 

void byte2bitsBox(bool *out,const unsigned char *in,int bits)  
{  
    for(int i=0;i<bits;i++)  
    {
        // 13→1101 注意写入顺序！
        out[3-i]=(in[i/8]>>(i%8)) &1;
    }
} 

void bit2byte(BYTE *out,const bool *in,int bits)  
{  
    memset(out,0,bits/8);  
    for(int i=0;i<bits;i++)  
        out[i/8]|=in[i]<<(7-(i%8));         // 注意高低位顺序，(7-(i%8))
}

void reverse_byBit(BYTE *out, const BYTE *in)
{
    bool in_bit[64];
    byte2bit(in_bit, in, 64);
    bool out_bit[64];
    for (int i=0; i<64; i++)
    {
        out_bit[64-i-1] = in_bit[i];
    }
    bit2byte(out, out_bit, 64);
}

void reverse_byByte(BYTE *out, const BYTE *in)
{
    for (int i=0; i<8; i++)
    {
        out[7-i] = in[i];
    }
}

// Input: keyByte, dataByte
// Output: unsigned char - encryptDataByte
void des_encrypt(BYTE *keyByte, BYTE *dataByte, BYTE *encryptDataByte)
{
    // ####### Set key ####### 
    BYTE keyByte_reverse[8];
    reverse_byBit(keyByte_reverse, keyByte);
    BYTE dataByte_reverse[8];
    reverse_byBit(dataByte_reverse, dataByte);

    // ####### init 16 groups subkey #######
    des_setkey(keyByte_reverse);

    // ####### encrypt #######
    BYTE result_encrypt[8];
    des_run(result_encrypt, dataByte_reverse, encrypt);
    // reverse result for output
    reverse_byBit(encryptDataByte, result_encrypt);
}

// Quick demo for DES encrypt/decrypt
void des_demo()
{
    // ####### Set key #######
    //F1 3F AE CC 83 81 BF A1
    unsigned char keyByteunsign[] = {0xf1, 0x3f, 0xae, 0xcc, 0x83, 0x81, 0xbf, 0xa1};
    unsigned char dataByteunsign[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    BYTE keyByte_reverse[8];
    reverse_byBit(keyByte_reverse, keyByteunsign);
    BYTE dataByte_reverse[8];
    reverse_byBit(dataByte_reverse, dataByteunsign);

    cout << "key(hex)" << endl;
    printHexByByte(keyByteunsign, 8);
    cout << "reversed key(hex)" << endl;
    printHexByByte(keyByte_reverse, 8);

    // ####### Set data #######
    cout << "data(hex)" << endl;
    printHexByByte(dataByteunsign, 8);
    cout << "reversed data(hex)" << endl;
    printHexByByte(dataByte_reverse, 8);

    // ####### init 16 groups subkey #######
    puts("\n***************** Start DES ***********************");
    des_setkey(keyByte_reverse);

    BYTE result_encrypt[8];
    // ####### encrypt #######
    des_run(result_encrypt, dataByte_reverse, encrypt);

    BYTE result_encrypt_reverse[8];
    reverse_byBit(result_encrypt_reverse, result_encrypt);

    puts("after encrypting:");
    cout << "result(hex)" << endl;
    printHexByByte(result_encrypt, 8);
    cout << "reversed result(hex)" << endl;
    printHexByByte(result_encrypt_reverse, 8);

    // ####### decrypt #######
    puts("after decrypting:");
    BYTE result_decrypt[8];
    des_run(result_decrypt, result_encrypt, decrypt);
    cout << "decrypt result(hex)" << endl;
    printHexByByte(result_decrypt, 8);
    puts("\n***************** End DES ***********************");  
}