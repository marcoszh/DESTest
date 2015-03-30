//
//  main.c
//  DESTest
//
//  Created by Marcos on 3/30/15.
//  Copyright (c) 2015 Marcos. All rights reserved.
//
#include "DES.h"

int main()
{
    int i, n;
    //文件名
    char filename[100];
    
    printf("Please input the bmp to be encrypted:\n");
    scanf("%s",filename);
    getchar();
    //打开文件
    fptr=fopen(filename, "rb");
    if (fptr==NULL)
    {
        printf("Open file failed\n");
        exit(1);
    }
    
    fseek(fptr,0,SEEK_END);
    size=ftell(fptr);
    fseek(fptr,0,SEEK_SET);
    
    srand(time(0));
    for (i=0;i<64;i++)
        random_key[i]=rand()%2;
    
    
    printf("Please input the key:");
    i=0;
    userkey[i]=getchar();
    while (userkey[i]!='\n')
    {
        i++;
        userkey[i]=getchar();
    }

    generate_password(userkey, bkey);
    
    to_char_array(key, bkey);
    
    //得到56位key
    replace(key, pc1, n=56);
    
    get_subkey(key);
    
    
    printf("Encryption mode: \"e\" (ECB)or \"c\"(CBC)\n");
    char flag;
    flag=getchar();
    char des_file[] = "encrypted_.bmp\0";
    des_file[9]=flag;
    //加密后的文件
    dfptr=fopen(des_file, "wb");

    getbmphead(fptr, dfptr);
    
    start_encrypt(flag);
    
    fclose(fptr);
    fclose(dfptr);
    printf("Encryption done！\n");
    
    printf("Decrypting......\n");
    fptr=fopen(des_file, "rb");
    dfptr=fopen("decrypted.bmp", "wb+");
    getbmphead(fptr, dfptr);
    start_decrypt(flag);        fclose(fptr);
    fclose(dfptr);
    printf("Encryption done！\n");
    
    return 0;
}










