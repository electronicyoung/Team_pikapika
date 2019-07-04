#include "AES-GCM-Decrypt.h"
//#include "aes-gcm.h"

uint8_t text[27][16];

uint8_t encrypted_msg[27][16];

uint8_t counter[27][16];

uint8_t encrypt_msg[16] = { 0 };

uint8_t Hash_text[16] = { 0 };

uint8_t Rconstant[44] = {0x00, 0x00, 0x00, 0x00};

uint8_t init_encrypt_msg[16] = { 0 };

uint32_t *length_cipher[2] = { 0 };
uint32_t *length_add[2] = { 0 };

uint32_t Total_length[4] = { 0,0,0,0 };

uint32_t tag[4] = { 0,0,0,0 };

uint8_t auth_text[2][16] = { 0 };
    
struct Round_keys {
    uint8_t keys[16];    
};

struct Round_keys No_of_Expanded_keys[11];

void AES_Encrypt(uint8_t msg[], uint8_t enc_msg[], uint8_t keys[]) {
    int k, i;
    uint8_t sub_text[16];
    uint8_t shift_text[16];
    uint8_t mix_text[16];
    
    RoundKeys(msg, keys, enc_msg);

    for(k=1;k<11;k++) {
        if(k == 10) {
            Subbyte(enc_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);

            RoundKeys(shift_text, No_of_Expanded_keys[k].keys, enc_msg);

            printf("last round enc_msg : ");
            for(i=0; i<16; i++){
                printf("%02x", enc_msg[i]);
            }
            printf("\n");
            
        }
          else {
            Subbyte(enc_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);

            mixcolumn(shift_text, mix_text);

            RoundKeys(mix_text, No_of_Expanded_keys[k].keys, enc_msg);

        }
    }
}

uint8_t msb_finder(uint32_t input){
  uint32_t bit_mask = 0x01;
  uint32_t temp = input;

  return ((temp & bit_mask));
}
void galois_multiply(uint32_t x[4], uint32_t y[4], uint32_t z[4]){
    uint32_t bit_shifter = 0x80000000;
    unsigned char i =0;
    unsigned char j =0;
    unsigned char v_lsb_flag = 0;
    uint32_t temp;
    uint32_t temp2;
    uint32_t temp3;

    uint32_t v[4] = {0,0,0,0};

    uint32_t r[4] = {0,0,0,0};

    memcpy(&v[0], &y[0], 4);
    memcpy(&v[1], &y[1], 4);
    memcpy(&v[2], &y[2], 4);
    memcpy(&v[3], &y[3], 4);

    r[0] = 0xe1000000;

    for( i=0; i<4; i++){
        temp = (uint32_t)x[i];//copy y to temp
        for( j=0; j<32; j++){
            if( ( temp & bit_shifter) == bit_shifter){//bit masking one by one
                temp3 = ( (uint32_t)z[0] ^ (uint32_t)v[0] );
                z[0] = temp3;
                temp3 = ( (uint32_t)z[1] ^ (uint32_t)v[1] );
                z[1] = temp3;
                temp3 = ( (uint32_t)z[2] ^ (uint32_t)v[2] );
                z[2] = temp3;
                temp3 = ( (uint32_t)z[3] ^ (uint32_t)v[3] );
                z[3] = temp3;

            }
            if(msb_finder(v[3])){//When LSB of Vi is 0
            v_lsb_flag = 1;
 
            }

          //order is 0 1 2 3 >>>>> moving this way

            v[3] = v[3] >> 1;

            temp2 = v[2];
            if(msb_finder(temp2)){//if lsb of v[1] is '1'
               v[3] = (uint32_t)v[3] |  0x80000000;//write MSB as 1
            }
            v[2] = v[2] >> 1;

            temp2 = v[1];
            if(msb_finder(temp2)){
               v[2] = (uint32_t)v[2] |  0x80000000;
            }

            v[1] = v[1] >> 1;

            temp2 = v[0];
            if(msb_finder(temp2)){
               v[1] = (uint32_t)v[1] |  0x80000000;
            }
            v[0] = v[0] >> 1;
            if( v_lsb_flag == 1){
               // v[3] = v[3] ^ r[3];
               // v[2] = v[2] ^ r[2];
               // v[1] = v[1] ^ r[1];
                v[0] = v[0] ^ r[0];
                v_lsb_flag = 0;
            }
            bit_shifter = bit_shifter >> 1;
        }//end of 32bit loop
        bit_shifter = 0x80000000;
    }
}

void Ghash(uint32_t input_Z[4], uint32_t input_A[4], uint32_t input_B[4], int counts, uint8_t auth_data[], int auth_len, int cipher_count) {

    //need to remove the number of zeros in ciphertext end result and don't use padded encrypt bits
    //replace them by zero before xoring in ciphertext with plaintext
    //memcpy shifting
    //decryption in aes gcm

    int k,i,l,m;
    uint32_t temp;

    for(k=0;k<counts;k++) {

      int byte_len = auth_len/8;

      if(k == 0 && byte_len != 0) {
          int text_count = 0;
          int auth_count = 0;

        while(byte_len > 0) {
          if(byte_len >= 16) {
             for(l=0;l<16;l++) {
               auth_text[auth_count][l] = auth_data[text_count];
               text_count = text_count + 1;
             }
             byte_len = byte_len - 16;
             auth_count++;
          }
          else if(byte_len < 16){
            int zero_pad = 16 - byte_len;

            for(i=0;i<byte_len;i++) {
                auth_text[auth_count][i] = auth_data[text_count];
                text_count = text_count + 1;
            }

            for(i=byte_len;i<zero_pad;i++) {
                auth_text[auth_count][i] = 0x00;
            }
            byte_len = 0;
            auth_count++;
          }
        }

        for(i=0;i<auth_count;i++) {
            memcpy(&input_A[0], auth_text[i], 4);
            memcpy(&input_A[1], auth_text[i]+4, 4);
            memcpy(&input_A[2], auth_text[i]+8, 4);
            memcpy(&input_A[3], auth_text[i]+12, 4);

            memcpy(&input_B[0], Hash_text, 4);
            memcpy(&input_B[1], Hash_text+4, 4);
            memcpy(&input_B[2], Hash_text+8, 4);
            memcpy(&input_B[3], Hash_text+12, 4);


            for(m=0;m<4;m++) {
               temp = (((uint32_t)input_A[m] & 0xFF000000 )>>24) | (((uint32_t)input_A[m] & 0x00FF0000) >> 8) | (((uint32_t)input_A[m] & 0x0000FF00) << 8) | (((uint32_t)input_A[m] & 0x000000FF) << 24);
               //input_A[m] = ((temp & 0xFF000000 )>>24) | ((temp & 0x00FF0000) >> 8) | ((temp & 0x0000FF00) << 8) | ((temp & 0x000000FF) << 24);
               input_A[m] = temp;
               temp = (((uint32_t)input_B[m] & 0xFF000000 )>>24) | (((uint32_t)input_B[m] & 0x00FF0000) >> 8) | (((uint32_t)input_B[m] & 0x0000FF00) << 8) | (((uint32_t)input_B[m] & 0x000000FF) << 24);
               input_B[m] = temp;
            }

            if(i > 0) {
                for(m=0;m<4;m++) {
                   uint32_t temp5;
                   temp5 = ((uint32_t)input_A[m] ^ (uint32_t)input_Z[m]);
                   input_A[m] = temp5;
                }
            }

            input_Z[0] = 0;
            input_Z[1] = 0;
            input_Z[2] = 0;
            input_Z[3] = 0;

            galois_multiply(input_A, input_B, input_Z);
            printf("After auth galois");
            printf("\n");
            
            printf("%02lx\n", input_Z[0]);
            printf("%02lx\n", input_Z[1]);
            printf("%02lx\n", input_Z[2]);
            printf("%02lx\n", input_Z[3]);
            
            printf("\n");
            
        }

        memcpy(&input_A[0], encrypted_msg[0], 4);
        memcpy(&input_A[1], encrypted_msg[0]+4, 4);
        memcpy(&input_A[2], encrypted_msg[0]+8, 4);
        memcpy(&input_A[3], encrypted_msg[0]+12, 4);

        for(m=0;m<4;m++) {
          temp = (((uint32_t)input_A[m] & 0xFF000000 )>>24) | (((uint32_t)input_A[m] & 0x00FF0000) >> 8) | (((uint32_t)input_A[m] & 0x0000FF00) << 8) | (((uint32_t)input_A[m] & 0x000000FF) << 24);
          input_A[m] = temp;
        }

        for(m=0;m<4;m++) {
            temp = (uint32_t)input_A[m] ^ (uint32_t)input_Z[m];
            input_A[m] = temp;
        }

        input_Z[0] = 0;
        input_Z[1] = 0;
        input_Z[2] = 0;
        input_Z[3] = 0;

        galois_multiply(input_A, input_B, input_Z);
        printf("Message loop galois");
        printf("\n");
            
            printf("%02lx\n", input_Z[0]);
            printf("%02lx\n", input_Z[1]);
            printf("%02lx\n", input_Z[2]);
            printf("%02lx\n", input_Z[3]);
            
            printf("\n");

      }
      else {
       memcpy(&input_A[0], encrypted_msg[k], 4);
       memcpy(&input_A[1], encrypted_msg[k]+4, 4);
       memcpy(&input_A[2], encrypted_msg[k]+8, 4);
       memcpy(&input_A[3], encrypted_msg[k]+12, 4);

       memcpy(&input_B[0], Hash_text, 4);
       memcpy(&input_B[1], Hash_text+4, 4);
       memcpy(&input_B[2], Hash_text+8, 4);
       memcpy(&input_B[3], Hash_text+12, 4);

        printf("Another copied data\n");
       for(m=0;m<4;m++) {
          temp = (((uint32_t)input_A[m] & 0xFF000000 )>>24) | (((uint32_t)input_A[m] & 0x00FF0000) >> 8) | (((uint32_t)input_A[m] & 0x0000FF00) << 8) | (((uint32_t)input_A[m] & 0x000000FF) << 24);
          //input_A[m] = ((temp & 0xFF000000 )>>24) | ((temp & 0x00FF0000) >> 8) | ((temp & 0x0000FF00) << 8) | ((temp & 0x000000FF) << 24);
          input_A[m] = temp;
          printf("%02lx", input_A[m]);
          temp = (((uint32_t)input_B[m] & 0xFF000000 )>>24) | (((uint32_t)input_B[m] & 0x00FF0000) >> 8) | (((uint32_t)input_B[m] & 0x0000FF00) << 8) | (((uint32_t)input_B[m] & 0x000000FF) << 24);
          input_B[m] = temp;
         
          
       }

      if(k > 0) {
          for(i=0;i<4;i++) {
            temp = (uint32_t)input_A[i] ^ (uint32_t)input_Z[i];
            input_A[i] = temp;
          }
      }

      input_Z[0] = 0;
      input_Z[1] = 0;
      input_Z[2] = 0;
      input_Z[3] = 0;

      galois_multiply(input_A, input_B, input_Z);
            
      printf("Message loop galois");
        printf("\n");
            
            printf("%02lx\n", input_Z[0]);
            printf("%02lx\n", input_Z[1]);
            printf("%02lx\n", input_Z[2]);
            printf("%02lx\n", input_Z[3]);
            
            printf("\n");
            
      Total_length[1] = (uint32_t)auth_len;
      Total_length[3] = (uint32_t)cipher_count;
 
      printf("\n");
      printf("The length of cipher_count %ld and auth_count %ld", Total_length[3],  Total_length[1]);
      printf("\n");
      
      if(k == counts - 1) {

         for(l=0;l<4;l++) {
            uint32_t temp3 = (uint32_t)Total_length[l];
            uint32_t temp4 = (uint32_t)input_Z[l];
            temp3 = temp3 ^ temp4;
            input_A[l] = temp3;
         }

         input_Z[0] = 0;
         input_Z[1] = 0;
         input_Z[2] = 0;
         input_Z[3] = 0;

         galois_multiply(input_A, input_B, input_Z);

        printf("Final GHASH");
        printf("\n");
            
            printf("%02lx\n", input_Z[0]);
            printf("%02lx\n", input_Z[1]);
            printf("%02lx\n", input_Z[2]);
            printf("%02lx\n", input_Z[3]);
            
            printf("\n");
        
         memcpy(&input_A[0], init_encrypt_msg, 4);
         memcpy(&input_A[1], init_encrypt_msg+4, 4);
         memcpy(&input_A[2], init_encrypt_msg+8, 4);
         memcpy(&input_A[3], init_encrypt_msg+12, 4);

         for(i=0;i<4;i++) {
           temp = (((uint32_t)input_A[i] & 0xFF000000 )>>24) | (((uint32_t)input_A[i] & 0x00FF0000) >> 8) | (((uint32_t)input_A[i] & 0x0000FF00) << 8) | (((uint32_t)input_A[i] & 0x000000FF) << 24);
           input_A[i] = temp;
         }

         printf("\n");
         printf("The tag is\n");
         for(i=0;i<4;i++) {
             uint32_t temp1 = (uint32_t)input_A[i];
             uint32_t temp2 = (uint32_t)input_Z[i];
             tag[i] = temp1 ^ temp2;
             printf("%02lx", tag[i]);
         }
         printf("\n");
 
      }
    }
  }
}

void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]) {
    unsigned char i;
    for(i=0; i<16; i++) {
        encrypted_message[i] = plain_message[i] ^ cipher_key[i];
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

  uint8_t sbox[256] = {
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

  for( i = 0; i < length; i++){
      row_num = (plain_text[i] & 0xF0) >> 4;
      col_num = plain_text[i] & 0x0F;
      transfered_text[i] = sbox[16*row_num + col_num];
  }
}

void Rcon(uint8_t *Rcon) {
    int j;
   for(j=4; j<40; j++) {
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
    int k, i;
    int count = 0;
    
    uint8_t rotated_block[4];
    uint8_t sub_block[4];

    for( k=0;k<11;k++) {
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
      uint8_t temp[6];
      int i;
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
    //uint8_t temp;
    int i;
    for( i = 0; i<4; i++){
      //temp = shifted_text[i*4] ^ shifted_text[i*4 +1] ^ shifted_text[i*4 + 2] ^ shifted_text[i*4 + 3];
      mixed_text[i*4]     = (multiply(shifted_text[i*4]))^(multiply(shifted_text[(i*4)+1])^shifted_text[(i*4)+1])^shifted_text[(i*4)+2]^shifted_text[(i*4)+3];
      mixed_text[i*4+1]   = shifted_text[i*4]^(multiply(shifted_text[i*4+1]))^(multiply(shifted_text[i*4+2])^shifted_text[i*4+2])^shifted_text[i*4+3];
      mixed_text[i*4+2]   = shifted_text[i*4]^shifted_text[i*4+1]^(multiply(shifted_text[i*4+2]))^(multiply(shifted_text[i*4+3])^shifted_text[i*4+3]);
      mixed_text[i*4+3]   = (multiply(shifted_text[i*4])^shifted_text[i*4])^shifted_text[i*4+1]^shifted_text[i*4+2]^(multiply(shifted_text[i*4+3]));
//in case of * 3 => use a multiply function to target value and xor the target value after the multiply function.
//3x = (2x + x) = mult(x) xor (x)
    }
}

void initialization_counter(uint8_t vector[], int count) {
    uint8_t incr = 0x01;
    int k, i;
    for( k=0;k<=count;k++) {
        for( i=0;i<16;i++) {
            if(i == 12 || i == 13 || i == 14) {
                counter[k][i] = 0x00;
            }
            else if(i == 15){
                 counter[k][i] = incr;
                incr = incr + 1;
            }
            else {
                counter[k][i] = vector[i];
            }

        }

    }
}

int plaintext_block(uint8_t *plaintext, int text_length, uint8_t *total_msg) {
     int i;
     int text_count = 0;
     int counts = 0;
     
     while(text_length > 0) {
         if(text_length >= 16) {
           for( i=0;i<16;i++) {
             text[counts][i] = plaintext[text_count];
             text_count = text_count + 1;
           }
           text_length = text_length - 16;
           counts++;
         }
         else if(text_length < 16){
            int zero_pad = 16 - text_length;

            for( i=0;i<text_length;i++) {
                text[counts][i] = plaintext[text_count];
                text_count = text_count + 1;
            }

            *total_msg = text_length;
            
            for( i=text_length;i<zero_pad;i++) {
                text[counts][i] = 0x00;
            }
            text_length = 0;
            counts++;
        }
    }

    return counts;

}

void main_decrypt(uint8_t message[], uint8_t encrypted_message[], int msg_length)
{
    /* Call driver init functions */
    int i, j;

    uint32_t Z[4] = {0,0,0,0};

    uint32_t A[4];
    uint32_t B[4];  

     
    for(i=0;i<27;i++) {
       for(j=0;j<16;j++) {
          text[i][j] = 0;
          encrypted_msg[i][j] = 0;
          counter[i][j] = 0;
       }       
    }
    
    
    uint8_t input_length = 0;
    
    uint32_t rec_tag[4] = { 0,0,0,0 };
/*  
    uint8_t add[] = {0xfe, 0xed, 0xfa, 0xce,
                     0xde, 0xad, 0xbe, 0xef,
                     0xfe, 0xed, 0xfa, 0xce,
                     0xde, 0xad, 0xbe, 0xef,
                     0xab, 0xad, 0xda, 0xd2
    };
*/
    uint8_t add[] = {};
    
    uint8_t iv[12];
    
    uint8_t mesg[100];
    
    uint8_t Hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    printf("The message length is %d\n", msg_length);

    int cipher_length = (msg_length-28)*8;
    
    printf("The cipher length is %d\n", cipher_length);
    
    int auth_length = (sizeof(add)/sizeof(uint8_t))*8;
    
    printf("The auth length is %d\n", auth_length);
    

    uint8_t key[]= {0xfe,0xff,0xe9,0x92,
                    0x86,0x65,0x73,0x1c,
                    0x6d,0x6a,0x8f,0x94,
                    0x67,0x30,0x83,0x08
                                       };
/*
     uint8_t key[]= {0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00
                                       };
                                       
 */                                     
    memcpy(&rec_tag[0], message, 4);
    memcpy(&rec_tag[1], message+4, 4);
    memcpy(&rec_tag[2], message+8, 4);
    memcpy(&rec_tag[3], message+12, 4);
    
    printf("The Original message is");
    for(i=0;i<msg_length;i++) {
        printf("%02x", message[i]);   
    }
    
    printf("The tag id is\n");
    for(i=0;i<4;i++) {
        volatile uint32_t temp = rec_tag[i];
        rec_tag[i] = ((temp & 0xFF000000 )>>24) | ((temp & 0x00FF0000) >> 8) | ((temp & 0x0000FF00) << 8) | ((temp & 0x000000FF) << 24);
        printf("%02lx", rec_tag[i]);
    }
   
    for(i=16;i<28;i++) {
        iv[i-16] = message[i];
    }
      
    for(i=28;i<msg_length;i++) {
         mesg[i-28] = message[i];
    }

    Rconstant[0] = 0x01;
    Rcon(Rconstant);

    keyExpansion(key);

    int counts = plaintext_block(mesg, (msg_length-28), &input_length);
    initialization_counter(iv,counts);

    printf("The Original message is");
    for(i=0;i<msg_length;i++) {
        printf("%02x", message[i]);   
    }
    
    printf("\n");
    
    printf("The plaintext block is");
    for(i=0; i<counts;i++) {
        for(j=0;j<16;j++) {
            printf("%02x", text[i][j]);
        }
        printf("\n");

    }

    AES_Encrypt(Hash, Hash_text, key);

    AES_Encrypt(counter[0], init_encrypt_msg, key);

    int pl_len = 0;
    
    for( j=0;j<counts;j++){

        int c = j+1;
        AES_Encrypt(counter[c], encrypt_msg, key);
            
        printf("The text is\n");
        if(j == counts - 1 && input_length != 0) {
            for(i=0;i<input_length;i++) {
                encrypted_message[pl_len] = text[j][i] ^ encrypt_msg[i];
                
                encrypted_msg[j][i] = text[j][i];
                pl_len = pl_len + 1;
                
            }
        }
        else {
            for(i=0;i<16;i++) {
                encrypted_message[pl_len] = text[j][i] ^ encrypt_msg[i];
                encrypted_msg[j][i] = text[j][i];
                printf("%02x", encrypted_message[pl_len]);
                pl_len = pl_len + 1;
            }           
        }
    }


    Ghash(Z, A, B, counts, add, auth_length, cipher_length);
   
    if(tag[0] != rec_tag[0] || tag[1] != rec_tag[1] || tag[2] != rec_tag[2] || tag[3] != rec_tag[3]) {
        for(i=0;i<pl_len;i++){
          encrypted_message[i] = 0;
        }
    }
   
    printf("plaintext is \n");
    for(i=0;i<pl_len;i++){
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");
}