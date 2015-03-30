//
//  DES.h
//  DESTest
//
//  Created by Marcos on 3/30/15.
//  Copyright (c) 2015 Marcos. All rights reserved.
//

#ifndef DESTest_DES_h
#define DESTest_DES_h

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#define MAX 100

//用户输入的key种子
unsigned char userkey[32];
//ECB使用的随机序列IV
unsigned char random_key[64];
unsigned char r_key[64];
unsigned char temp_key[64];
//十六轮使用的子密钥
unsigned char subkey[16][56];
//读取文件缓冲区
unsigned char M[8];
//按位分离存放
unsigned char m[64];
//密钥
unsigned char bkey[8];
//按位分离的密钥
unsigned char key[64];
//扩展后
unsigned char extend[48];
unsigned char encrypted_M[8]={0};
unsigned char zkey[56];


FILE* fptr=NULL, *dfptr;
long size;
unsigned char* L, *R;


//初始置换使用的表
static unsigned char ip[64]=
{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};


//初始置换IP的逆IP-1
static unsigned char ip1[64]=
{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

static unsigned char pc1[56]=  //密钥置换1
{
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};



static unsigned char pc2[48]=  //密钥置换2
{
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static unsigned char e[48]=  //扩充置换E
{
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static unsigned char lcircle[16]=  //每一轮要循环的次数
{
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};


static unsigned char s[8][4][16]=  //S表
{
    // S1
    14,	 4,	13,	 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    // S2
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    // S3
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    // S4
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    // S5
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    // S6
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    // S7
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    // S8
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6,  11
};



static unsigned char P[32]=  //置换P
{
    16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};

//根据口令产生64位密钥
void generate_password(unsigned char* pd, unsigned char* bkey);
//将8位char数组按位取出64位密钥
void to_char_array(unsigned char* des, unsigned char* src);
//64位二进制还原
void getchars(unsigned char* a, unsigned char* mw);
//置换函数
void replace(unsigned char* a, unsigned char* b, int n);
void S_box(unsigned char* a);

//获取子密钥
void get_subkey(unsigned char* key);
//进行16轮加密
void encrypt_cycle();
//进行16轮解密
void decrypt_cycle();
//将文件头直接复制
void getbmphead(FILE* fptr, FILE* dfptr);
//左移位
void left_shift(unsigned char* key, int n);
void XOR(unsigned char* a, unsigned char* b, int n);
int  add(unsigned char* a);
void start_encrypt(char flag);
void start_decrypt(char flag);


void generate_password(unsigned char* pd, unsigned char* bkey)//产生密钥大于64位截取，小于补全
{
    int i, j=0;
    
    for (i=0;i<8;i++)
    {
        //不够64，从头重复
        if (pd[j]=='\n')
        {
            j=0;
            i--;
        }
        else
        {
            bkey[i]=pd[j];
            j++;
        }
    }
    return ;
}



void start_encrypt(char flag)
{
    int i, n, j=0;
    //循环直至文件结束
    while (!feof(fptr))
    {
        
        fread(&M[0], 1, 8, fptr);
        //8字节转换到64位
        to_char_array(m, M);          //将明文转换为二进制
        
        //CBC模式IV
        if (j==0)
        {
            for (i=0;i<64;i++)
                r_key[i]=random_key[i];
        }
        //CBC，结果与明文异或
        if (flag=='c')
            XOR(m, r_key, 64);
        
        //第一次交换
        replace(m, ip, n=64);
        
        //获取左右两部分首地址
        L=&m[0];
        R=&m[32];
        
        encrypt_cycle();
        
        //逆初始值换
        replace(L, ip1, 64);
        for (i=0;i<64;i++)
            r_key[i]=L[i];
        getchars(L, encrypted_M);
        
        
        fwrite(&encrypted_M[0], 1, 8, dfptr);
        j++;
    }
}



void start_decrypt(char flag)
{
    int i, n,j=0;
    while (!feof(fptr))
    {
        fread(&M[0], 1, 8, fptr);
        //将每位分离
        to_char_array(m, M);
        
        //获取左右两部分的指针
        L=&m[0];
        R=&m[32];
        if (j==0)
        {
            for (i=0;i<64;i++)
                r_key[i]=random_key[i];
        }
        for (i=0;i<64;i++)
            temp_key[i]=L[i];
        //初始置换
        replace(m, ip, n=64);
        
        decrypt_cycle();
        
        //逆初始化置换
        replace(L, ip1, 64);
        
        //CBC模式
        if (flag=='c')
        {
            XOR(L, r_key, 64);
            for (i=0;i<64;i++)
                r_key[i]=temp_key[i];
        }
        getchars(L, encrypted_M);
        fwrite(&encrypted_M[0], 1, 8, dfptr);
        j++;
    }
}

void decrypt_cycle()
{
    int i, n, q;
    
    for (q=0;q<16;q++)            //************进入16轮迭代******************
    {
        for (i=0;i<56;i++)
            zkey[i]=subkey[15-q][i];
        
        replace(zkey, pc2, n=48); //密钥紧缩成48位
        for (i=0;i<32;i++)
            extend[i]=R[i];
        
        replace(extend, e, n=48);     //对右半部分进行扩充，到48位
        
        ///////////////////////////////////////////////////////////////////////////////////
        
        XOR(extend, zkey, n=48);      //右半部分与密钥（48位）进行异或
        
        S_box(extend);                //进入S盒操作
        replace(extend, P, n=32);     //对右半部分进行P置换
        
        ////////////////////////////////////////////////////////////////////////////////////
        
        XOR(extend, L, n=32);         //左右异或
        for (i=0;i<32;i++)        //左右交换
        {
            L[i]=R[i];
            R[i]=extend[i];
        }
        if (q==15)                //16次完毕再交换一次
        {
            for (i=0;i<32;i++)
            {
                extend[i]=R[i];
                R[i]=L[i];
                L[i]=extend[i];
            }
        }
    }
}


void encrypt_cycle()
{
    int i, n, q;
    
    //16轮
    for (q=0;q<16;q++)
    {
        //此轮使用的子密钥
        for (i=0;i<56;i++)
            zkey[i]=subkey[q][i];
        
        //置换成为48位
        n=48;
        replace(zkey, pc2, n);
        
        //前32位
        for (i=0;i<32;i++)
            extend[i]=R[i];
        
        //扩展
        n=48;
        replace(extend, e, n);
        //右半部分的异或
        XOR(extend, zkey, n);
        
        S_box(extend);
        n=32;
        replace(extend, P, n);
        
        XOR(extend, L, n=32);
        
        //左右交换顺序
        for (i=0;i<32;i++)
        {
            L[i]=R[i];
            R[i]=extend[i];
        }
        //最后一轮要交换得到输出
        if (q==15)
        {
            for (i=0;i<32;i++)
            {
                extend[i]=R[i];
                R[i]=L[i];
                L[i]=extend[i];
            }
        }
    }
    
}


void get_subkey(unsigned char* key)
{
    int i, j;
    for (i=0;i<16;i++)
    {
        left_shift(key, i);
        for (j=0;j<56;j++)
        {
            subkey[i][j]=key[j];      //得到16个子密钥
        }
    }
    return;
}

void to_char_array(unsigned char* des, unsigned char* src)
{
    int i, j;
    //掩码
    unsigned char a[8]={128, 64, 32, 16, 8, 4, 2, 1};
    for (i=0;i<8;i++)
    {
        for (j=0;j<8;j++)
        {
            if ((src[i]&a[j])==0)  //用与的方法取出对应的二进制位
                des[i*8+j]=0;
            else
                des[i*8+j]=1;
        }
    }
}


void replace(unsigned char* a, unsigned char* b, int n)

{
    int i;
    unsigned char c[MAX];            //进行置换
    for (i=0;i<n;i++)
        c[i]=a[b[i]-1];
    for (i=0;i<n;i++)
        a[i]=c[i];
    return;
}

void left_shift(unsigned char* key, int n)
{
    int i, j, k;
    
    switch (lcircle[n])              //密钥左循环：前28位循环左移，后28位循环左移
    {
        case 1:
            j=key[0];
            for (i=0;i<27;i++)
                key[i]=key[i+1];
            key[27]=j;
            
            j=key[28];
            for (i=28;i<55;i++)
                key[i]=key[i+1];
            key[55]=j;
            break;
        case 2:
            j=key[0];
            k=key[1];
            for (i=0;i<26;i++)
                key[i]=key[i+2];
            key[26]=j;
            key[27]=k;
            
            j=key[28];
            k=key[29];
            for (i=28;i<54;i++)
                key[i]=key[i+2];
            key[54]=j;
            key[55]=k;
            break;
    }
    
    return;
}

void XOR(unsigned char* a, unsigned char* b, int n)
{
    int i;
    for (i=0;i<n;i++)
        a[i]=a[i]^b[i];
    return;
}

void S_box(unsigned char* a)
{
    int i, j;
    unsigned char b[8][6];
    unsigned char c[8];
    //分8*6
    for (i=0;i<8;i++)
    {
        for (j=0;j<6;j++)
            b[i][j]=a[i*6+j];
    }
    //查表获取输出
    for (i=0;i<8;i++)
    {
        c[i]=s[i][ b[i][0]*2+b[i][5]][ b[i][1]*8+b[i][2]*4+b[i][3]*2+b[i][4]];
    }
    for (i=0;i<8;i++)               //将十进制转换成二进制
    {
        for (j=3;j>=0;j--)
        {
            a[i*4+j]=c[i]%2;
            c[i]/=2;
        }
    }
    return;
}


void getchars(unsigned char* a, unsigned char* dmw)
{
    int i;
    for (i=0;i<8;i++)
        dmw[i]=add(&a[i*8]);       //二进制转换成十进制char
    return;
}

int add(unsigned char* a)
{
    return a[0]*128+a[1]*64+a[2]*32+a[3]*16+a[4]*8+a[5]*4+a[6]*2+a[7];
}

void getbmphead(FILE* fptr, FILE* dfptr)
{
    int i;
    char c;
    
    for (i=0;i<54;i++)
    {
        c=fgetc(fptr);
        fputc(c, dfptr);
    }
}

#endif
