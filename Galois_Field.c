/*
 * Copyright (c) 2015-2019, Texas Instruments Incorporated
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * *  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * *  Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  ======== hello.c ========
 */

/* XDC Module Headers */
#include <xdc/std.h>
#include <xdc/runtime/System.h>

/* BIOS Module Headers */
#include <ti/sysbios/BIOS.h>

#include <ti/drivers/Board.h>

#include <stdio.h>
#include <stdint.h>

/*
 *  ======== main ========
 */

#include <stdint.h>

void keyExpansion(uint8_t *allocated_key);
void RotWord(uint8_t *col_block, uint8_t *rot_col_block);
void Subbyte(uint8_t *plain_text, uint8_t *transfered_text, unsigned int length);
void Rcon(uint8_t *Rcon);
void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]);
void shiftrow(uint8_t *transfered_text, uint8_t *shifted_text);
void mixcolumn(uint8_t *shifted_text, uint8_t *mixed_text);
uint8_t multiply(uint8_t value);

static const uint8_t sbox[256] = {
                  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
                  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

struct Round_keys {
    uint8_t keys[16];
};

struct Round_keys No_of_Expanded_keys[11];

uint8_t encrypt_msg[16];
uint8_t rotated_block[4];
uint8_t sub_block[4];

uint8_t sub_text[16];
uint8_t shift_text[16];
uint8_t mix_text[16];

uint8_t Rconstant[] = {0x01, 0x00, 0x00, 0x00};


void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]) {
    unsigned char i;
    for(i=0; i<16; i++) {
        encrypted_message[i] = plain_message[i] ^ cipher_key[i];
        //printf("%x", encrypt_msg[i]);
        //printf("%x ", encrypt_msg[i*4+1]);
        //printf("%x ", encrypt_msg[i*4+2]);
        //printf("%x\n", encrypt_msg[i*4+3]);
    }
}

void RotWord(uint8_t *col_block, uint8_t *rot_col_block) {
    rot_col_block[3] = col_block[0];
    rot_col_block[0] = col_block[1];
    rot_col_block[1] = col_block[2];
    rot_col_block[2] = col_block[3];
}

void Subbyte(uint8_t *plain_text, uint8_t *transfered_text, unsigned int length)
{
  uint8_t row_num, col_num = 0;
  int i;
  for(i = 0; i < length; i++){
      row_num = (plain_text[i] & 0xF0) >> 4;
      col_num = plain_text[i] & 0x0F;
      transfered_text[i] = sbox[16*row_num + col_num];
  }
}

void Rcon(uint8_t *Rcon) {
    int j;
   for( j=4; j<40; j++) {
       if(j == 32) {
           Rcon[j] = 0x1b;
       }
       else if(j == 36) {
           Rcon[j] = 0x36;
       }
       else {
           Rcon[j] = 2*Rcon[j-4];
       }
   }
}


void keyExpansion(uint8_t *allocated_key) {

    int count = 0;
    int k;
    int i;
    for(k=0;k<11;k++) {
        if(k == 0) {
          while(count < 16) {
              No_of_Expanded_keys[k].keys[count] = allocated_key[count];
              count = count + 1;
          }
          count = 0;
        }
        else {
            uint8_t key_block[] = {No_of_Expanded_keys[k-1].keys[12],No_of_Expanded_keys[k-1].keys[13],No_of_Expanded_keys[k-1].keys[14],No_of_Expanded_keys[k-1].keys[15]};
            RotWord(key_block, rotated_block);
            Subbyte(rotated_block, sub_block, 4);

            uint8_t first_key_block[] = {No_of_Expanded_keys[k-1].keys[0],No_of_Expanded_keys[k-1].keys[1],No_of_Expanded_keys[k-1].keys[2],No_of_Expanded_keys[k-1].keys[3]};

            for( i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i] = first_key_block[i] ^ sub_block[i] ^ Rconstant[count];
                count = count + 1;
            }

            for( i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+4] =  No_of_Expanded_keys[k].keys[i] ^ No_of_Expanded_keys[k-1].keys[i+4];
            }

            for( i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+8] =  No_of_Expanded_keys[k].keys[i+4] ^ No_of_Expanded_keys[k-1].keys[i+8];
            }

            for( i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+12] =  No_of_Expanded_keys[k].keys[i+8] ^ No_of_Expanded_keys[k-1].keys[i+12];
            }

        }

    }
}

void shiftrow(uint8_t *transfered_text, uint8_t *shifted_text)
{
    int i;
      uint8_t temp[6];
      temp[0] = transfered_text[1];

      temp[1] = transfered_text[2];
      temp[2] = transfered_text[6];

      temp[3] = transfered_text[3];
      temp[4] = transfered_text[7];
      temp[5] = transfered_text[11];

      for( i = 0; i<4; i++){
      shifted_text[4*i] = transfered_text[4*i];
      }
      shifted_text[1] = transfered_text[5];
      shifted_text[5] = transfered_text[9];
      shifted_text[9] = transfered_text[13];
      shifted_text[13] = temp[0];

      shifted_text[2] = transfered_text[10];
      shifted_text[6] = transfered_text[14];
      shifted_text[10] = temp[1];
      shifted_text[14] = temp[2];

      shifted_text[3] = transfered_text[15];
      shifted_text[7] = temp[3];
      shifted_text[11] = temp[4];
      shifted_text[15] = temp[5];
}

uint8_t multiply(uint8_t value)
{
  uint8_t temp = value;
  
  if(temp < 0x80){
    temp = temp << 1;
    return temp;
  }
  else{
    temp = temp << 1;
    temp = temp ^ 0x1b;
    return temp;
  }
}

void mixcolumn(uint8_t *shifted_text, uint8_t *mixed_text)
{
    int i;
    //uint8_t temp;
    for( i = 0; i<4; i++){
      //temp = shifted_text[i*4] ^ shifted_text[i*4 +1] ^ shifted_text[i*4 + 2] ^ shifted_text[i*4 + 3];
      mixed_text[i*4]     = (multiply(shifted_text[i*4]))^(multiply(shifted_text[(i*4)+1])^shifted_text[(i*4)+1])^shifted_text[(i*4)+2]^shifted_text[(i*4)+3];
      mixed_text[i*4+1]   = shifted_text[i*4]^(multiply(shifted_text[i*4+1]))^(multiply(shifted_text[i*4+2])^shifted_text[i*4+2])^shifted_text[i*4+3];
      mixed_text[i*4+2]   = shifted_text[i*4]^shifted_text[i*4+1]^(multiply(shifted_text[i*4+2]))^(multiply(shifted_text[i*4+3])^shifted_text[i*4+3]);
      mixed_text[i*4+3]   = (multiply(shifted_text[i*4])^shifted_text[i*4])^shifted_text[i*4+1]^shifted_text[i*4+2]^(multiply(shifted_text[i*4+3]));
//in case of * 3 => use a multiply function to target value and xor the target value after the multiply function.

    }
}




uint8_t msb_finder(uint32_t input){
  uint32_t bit_mask = 0x80000000;
  uint32_t temp = input;
  
  return (temp & bit_mask)>>31;
}

uint8_t lsb_finder(uint32_t input){
  uint32_t bit_mask = 0x1;
  uint32_t temp = input;
  
  return (temp & bit_mask);
}



void galois_multiply(uint32_t *x[4], uint32_t *y[4], uint32_t *z[4]){
    uint32_t bit_shifter = 0x01;
    unsigned char shift_cnt = 0;
    unsigned char i =0;
    unsigned char j =0;
    unsigned char v_lsb_flag = 0;
    uint32_t temp;
    uint32_t temp2;

    uint32_t v[4] = {0,0,0,0};
    uint32_t r[4] = {0,0,0,0};


    memcpy(&v[0], &y[0], 16);

    r[3] = (0xe1)<<24; // 0xe1 = 11100001

    for( i=0; i<4; i++){
        temp = x[i];//copy x to temp
        for( j=0; j<32; j++){
            if( ( temp & bit_shifter) == bit_shifter){//bit masking one by one
                z[0] = ( (uint32_t)z[0] ^ v[0] );
                z[1] = ( (uint32_t)z[1] ^ v[1] );
                z[2] = ( (uint32_t)z[2] ^ v[2] );
                z[3] = ( (uint32_t)z[3] ^ v[3] );
                
            }
           if( v[0] & 0x1 == 1){//When LSB of Vi is 0
            v_lsb_flag = 1;
               
           }
                
            v[0] = v[0] >> 1;
            
            temp2 = v[1];
            if(lsb_finder(temp2)){//if lsb of v[1] is '1'
                v[0] = (uint32_t)v[0] | 0x80000000;//write MSB as 1
            }
            v[1] = v[1] >> 1;
            
            temp2 = v[2];
            if(lsb_finder(temp2)){
                v[1] = (uint32_t)v[1] | 0x80000000;
            }
            v[2] = v[2] >> 1;
            
            temp2 = v[3];
            if(lsb_finder(temp2)){
                v[2] = (uint32_t)v[2] | 0x80000000;
            }
            v[3] = v[3] >> 1;
            
            if( v_lsb_flag == 1){
                v[3] = (v[3] >> 1) ^ r[3];
                v[2] = (v[2] >> 1) ^ r[2];
                v[1] = (v[1] >> 1) ^ r[1];
                v[0] = (v[0] >> 1) ^ r[0];
                v_lsb_flag = 0;
            }
            
            
            bit_shifter = bit_shifter << 1;

        }//end of 32bit loop
        bit_shifter = 0x1;
        
    }

}
 
 
int main()
{
    /* Call driver init functions */
    Board_init();

    char i,k;


    System_printf("Start!\n");

    uint32_t x[4], y[4], z[4];

    x[0] = 0xf4030201;
    x[1] = 0xf8070605;
    x[2] = 0xFFAAAAAA;
    x[3] = 0xAAAAAAAA;
    y[0] = 0xFFFFFFFF;
    y[1] = 0xFFFFFFFF;
    y[2] = 0xAAAAAAAA;
    y[3] = 0xAAAAAAAA;
    for( i = 0; i<4; i++){
        z[i]=0;
    }

    galois_multiply(x, y, z);
    uint32_t temp = 0x0FFFFFFF;
    

    System_printf("z[0] : %x\n", z[0]);
    System_printf("z[1] : %x\n", z[1]);
    System_printf("z[2] : %x\n", z[2]);
    System_printf("z[3] : %x\n", z[3]);






/*


    uint8_t message[] ={0x48,0x49,0x00,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00
                        };

    printf("Plain text : ");
    for( i=0; i<16; i++){
        printf("%x",message[i]);
    }
    printf("\n");
    uint8_t key[]= {0x21,0xab,0x71,0x03,
                    0xd6,0x82,0x79,0xad,
                    0xe0,0x45,0x2d,0x11,
                    0x25,0x2d,0x11,0x28
                    };



//21ab7103d68279ade0452d11252d1128


    //uint8_t key[]= {0x00,0x01,0x02,0x03,
      //              0x04,0x05,0x06,0x07,
        //            0x08,0x09,0x0a,0x0b,
          //          0x0c,0x0d,0x0e,0x0f
            //                           };

    printf("Key : ");
    for( i=0; i<16; i++){
        printf("%x",key[i]);
    }
    printf("\n");

    Rcon(Rconstant);
    keyExpansion(key);

    RoundKeys(message, key, encrypt_msg);


    //debug
    printf("round0 enc_msg : ");
    for( i=0; i<16; i++){
        printf("%x",encrypt_msg[i]);
    }
    printf("\n");

    for( k=1;k<11;k++) {
        if(k == 10) {
            Subbyte(encrypt_msg, sub_text, 16);
            printf("round %d sub_byte : ",k);
            for( i=0; i<16; i++){
                printf("%x",sub_text[i]);
            }
            printf("\n");

            shiftrow(sub_text, shift_text);
            printf("round %d Shiftrow : ",k);
            for( i=0; i<16; i++){
                printf("%x",shift_text[i]);
            }
            printf("\n");

            RoundKeys(shift_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("last round enc_msg : ");
            for( i=0; i<16; i++){
                printf("%02x",encrypt_msg[i]);
            }
            printf("\n");
        }
        else {
            Subbyte(encrypt_msg, sub_text, 16);
            printf("round %d sub_byte : ",k);
            for( i=0; i<16; i++){
                printf("%x",sub_text[i]);
            }
            printf("\n");

            shiftrow(sub_text, shift_text);
            printf("round %d Shiftrow : ",k);
            for( i=0; i<16; i++){
                printf("%x",shift_text[i]);
            }
            printf("\n");

            mixcolumn(shift_text, mix_text);
            printf("round %d mix_text : ",k);
            for( i=0; i<16; i++){
                printf("%x",mix_text[i]);
            }
            printf("\n");

            RoundKeys(mix_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("round %d enc_msg : ",k);
            for( i=0; i<16; i++){
                printf("%x",encrypt_msg[i]);
            }
            printf("\n");
        }
    }



*/


    /*
     *  normal BIOS programs, would call BIOS_start() to enable interrupts
     *  and start the scheduler and kick BIOS into gear.  But, this program
     *  is a simple sanity test and calls BIOS_exit() instead.
     */
    BIOS_exit(0);  /* terminates program and dumps SysMin output */
    return(0);
}
