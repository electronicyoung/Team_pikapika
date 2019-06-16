/******************************************************************************

Welcome to GDB Online.
GDB online is an online compiler and debugger tool for C, C++, Python, Java, PHP, Ruby, Perl,
C#, VB, Swift, Pascal, Fortran, Haskell, Objective-C, Assembly, HTML, CSS, JS, SQLite, Prolog.
Code, Compile, Run and Debug online from anywhere in world.

*******************************************************************************/
#include <stdio.h>
#include <stdint.h>

void keyExpansion(uint8_t *allocated_key);
void RotWord(uint8_t *col_block, uint8_t *rot_col_block);
void inv_Subbyte(uint8_t *plain_text, uint8_t *transfered_text, unsigned int length);
void Rcon(uint8_t *Rcon);
void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]);
void inv_shiftrow(uint8_t *transfered_text, uint8_t *shifted_text);
void Invmixcolumn(uint8_t *shifted_text, uint8_t *mixed_text);
uint8_t multiply(uint8_t value);


static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };



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

int main()
{

    uint8_t message[] ={0x69,0xc4,0xe0,0xd8,
                        0x6a,0x7b,0x04,0x30,
                        0xd8,0xcd,0xb7,0x80,
                        0x70,0xb4,0xc5,0x5a
                        };

    printf("Plain text : ");
    for(int i=0; i<16; i++){
        printf("%x",message[i]);
    }
    printf("\n");
    uint8_t key[]= {0x00,0x01,0x02,0x03,
                    0x04,0x05,0x06,0x07,
                    0x08,0x09,0x0a,0x0b,
                    0x0c,0x0d,0x0e,0x0f
                    };

    //uint8_t key[]= {0x00,0x01,0x02,0x03,
      //              0x04,0x05,0x06,0x07,
        //            0x08,0x09,0x0a,0x0b,
          //          0x0c,0x0d,0x0e,0x0f
            //                           };

    printf("Key : ");
    for(int i=0; i<16; i++){
        printf("%x",key[i]);
    }
    printf("\n");

    Rcon(Rconstant);
    keyExpansion(key);
    /*
    for(int k=0; k<11;k++){
        printf("The key number is %i\n", k);
        for(int i=0; i<16; i++) {
          printf("%x ", No_of_Expanded_keys[k].keys[i*4]);
          printf("%x ", No_of_Expanded_keys[k].keys[i*4+1]);
          printf("%x ", No_of_Expanded_keys[k].keys[i*4+2]);
          printf("%x\n", No_of_Expanded_keys[k].keys[i*4+3]);
      }
    }
    */
    RoundKeys(message, No_of_Expanded_keys[10].keys, encrypt_msg);


    //debug
    printf("round0 enc_msg : ");
    for(int i=0; i<16; i++){
        printf("%x",encrypt_msg[i]);
    }
    printf("\n");

    for(int k=9;k>=0;k--) {
        if(k == 0) {
            inv_Subbyte(encrypt_msg, sub_text, 16);
            printf("round %d sub_byte : ",k);
            for(int i=0; i<16; i++){
                printf("%x",sub_text[i]);
            }
            printf("\n");

            inv_shiftrow(sub_text, shift_text);
            printf("round %d Shiftrow : ",k);
            for(int i=0; i<16; i++){
                printf("%x",shift_text[i]);
            }
            printf("\n");

            RoundKeys(shift_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("last round enc_msg : ");
            for(int i=0; i<16; i++){
                printf("%02x",encrypt_msg[i]);
            }
            printf("\n");
        }
        else {
            inv_Subbyte(encrypt_msg, sub_text, 16);
            printf("round %d sub_byte : ",k);
            for(int i=0; i<16; i++){
                printf("%x",sub_text[i]);
            }
            printf("\n");

            inv_shiftrow(sub_text, shift_text);
            printf("round %d Shiftrow : ",k);
            for(int i=0; i<16; i++){
                printf("%x",shift_text[i]);
            }
            printf("\n");

            Invmixcolumn(shift_text, mix_text);
            printf("round %d mix_text : ",k);
            for(int i=0; i<16; i++){
                printf("%x",mix_text[i]);
            }
            printf("\n");

            RoundKeys(mix_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("round %d enc_msg : ",k);
            for(int i=0; i<16; i++){
                printf("%x",encrypt_msg[i]);
            }
            printf("\n");
        }
    }

    return 0;

}

void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]) {
    for(uint8_t i=0; i<16; i++) {
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

void inv_Subbyte(uint8_t *plain_text, uint8_t *transfered_text, unsigned int length)
{
  uint8_t row_num, col_num = 0;

  for(int i = 0; i < length; i++){
      row_num = (plain_text[i] & 0xF0) >> 4;
      col_num = plain_text[i] & 0x0F;
      transfered_text[i] = rsbox[16*row_num + col_num];
  }
}

void Rcon(uint8_t *Rcon) {

   for(int j=4; j<40; j++) {
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
    for(int k=0;k<11;k++) {
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
            inv_Subbyte(rotated_block, sub_block, 4);

            uint8_t first_key_block[] = {No_of_Expanded_keys[k-1].keys[0],No_of_Expanded_keys[k-1].keys[1],No_of_Expanded_keys[k-1].keys[2],No_of_Expanded_keys[k-1].keys[3]};

            for(int i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i] = first_key_block[i] ^ sub_block[i] ^ Rconstant[count];
                count = count + 1;
            }

            for(int i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+4] =  No_of_Expanded_keys[k].keys[i] ^ No_of_Expanded_keys[k-1].keys[i+4];
            }

            for(int i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+8] =  No_of_Expanded_keys[k].keys[i+4] ^ No_of_Expanded_keys[k-1].keys[i+8];
            }

            for(int i=0; i<4; i++){
                No_of_Expanded_keys[k].keys[i+12] =  No_of_Expanded_keys[k].keys[i+8] ^ No_of_Expanded_keys[k-1].keys[i+12];
            }

        }

    }
}

void inv_shiftrow(uint8_t *transfered_text, uint8_t *shifted_text)
{
      uint8_t temp[6];
      temp[0] = transfered_text[13];

      temp[1] = transfered_text[10];
      temp[2] = transfered_text[14];

      temp[3] = transfered_text[7];
      temp[4] = transfered_text[11];
      temp[5] = transfered_text[15];

      for(int i = 0; i<4; i++){
      shifted_text[4*i] = transfered_text[4*i];
      }
      shifted_text[1] = temp[0];
      shifted_text[5] = transfered_text[1];
      shifted_text[9] = transfered_text[5];
      shifted_text[13] = transfered_text[9];

      shifted_text[2] = temp[1];
      shifted_text[6] = temp[2];
      shifted_text[10] = transfered_text[2];
      shifted_text[14] = transfered_text[6];

      shifted_text[3] = temp[3];;
      shifted_text[7] = temp[4];
      shifted_text[11] = temp[5];
      shifted_text[15] = transfered_text[3];
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

void Invmixcolumn(uint8_t *shifted_text, uint8_t *mixed_text)
{
    //uint8_t temp;
    for(int i = 0; i<4; i++){

      mixed_text[i*4]     = multiply(multiply(multiply(shifted_text[i*4]) ^ shifted_text[i*4]) ^ shifted_text[i*4]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+1])) ^ shifted_text[i*4+1]) ^ shifted_text[i*4+1]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+2]) ^ shifted_text[i*4+2])) ^ shifted_text[i*4+2]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+3]))) ^ shifted_text[i*4+3]);

      mixed_text[i*4+1]   = (multiply(multiply(multiply(shifted_text[i*4]))) ^ shifted_text[i*4]) ^
                            multiply(multiply(multiply(shifted_text[i*4+1]) ^ shifted_text[i*4+1]) ^ shifted_text[i*4+1]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+2])) ^ shifted_text[i*4+2]) ^ shifted_text[i*4+2]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+3]) ^ shifted_text[i*4+3])) ^ shifted_text[i*4+3]);

      mixed_text[i*4+2]   = (multiply(multiply(multiply(shifted_text[i*4]) ^ shifted_text[i*4])) ^ shifted_text[i*4]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+1]))) ^ shifted_text[i*4+1]) ^
                            multiply(multiply(multiply(shifted_text[i*4+2]) ^ shifted_text[i*4+2]) ^ shifted_text[i*4+2]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+3])) ^ shifted_text[i*4+3]) ^ shifted_text[i*4+3]);

      mixed_text[i*4+3]   = (multiply(multiply(multiply(shifted_text[i*4])) ^ shifted_text[i*4]) ^ shifted_text[i*4]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+1]) ^ shifted_text[i*4+1])) ^ shifted_text[i*4+1]) ^
                            (multiply(multiply(multiply(shifted_text[i*4+2]))) ^ shifted_text[i*4+2]) ^
                            multiply(multiply(multiply(shifted_text[i*4+3]) ^ shifted_text[i*4+3]) ^ shifted_text[i*4+3]);

    }
}
