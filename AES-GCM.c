/******************************************************************************

Welcome to GDB Online.
GDB online is an online compiler and debugger tool for C, C++, Python, Java, PHP, Ruby, Perl,
C#, VB, Swift, Pascal, Fortran, Haskell, Objective-C, Assembly, HTML, CSS, JS, SQLite, Prolog.
Code, Compile, Run and Debug online from anywhere in world.

*******************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int plaintext_block(uint8_t *plaintext, int text_length, int cnt);
void initialization_counter(uint8_t vector[], int count);
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

uint8_t text[20][16] = { 0 };

uint8_t encrypted_msg[20][16] = { 0 };
uint8_t counter[20][20] = { 0 };

int counting = 0;

struct Round_keys No_of_Expanded_keys[11];

uint8_t encrypt_msg[16];
uint8_t rotated_block[4];
uint8_t sub_block[4];

uint8_t sub_text[16];
uint8_t shift_text[16];
uint8_t mix_text[16];

uint8_t Hash_text[16];

uint8_t Rconstant[] = {0x01, 0x00, 0x00, 0x00};

int main()
{

    uint8_t message[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    uint8_t Hash[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   
    uint8_t iv[] ={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    
    int msg_length = sizeof(message)/sizeof(uint8_t);
    
    uint8_t key[]= {0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00
                                       };

    Rcon(Rconstant);
    keyExpansion(key);
   
    int count = plaintext_block(message,msg_length,counting);
    initialization_counter(iv,count);
   
    RoundKeys(Hash, key, encrypt_msg);
    
    for(int k=1;k<11;k++) {
        if(k == 10) {
            Subbyte(encrypt_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);

            RoundKeys(shift_text, No_of_Expanded_keys[k].keys, encrypt_msg);
        }
          else {
            Subbyte(encrypt_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);
            
            mixcolumn(shift_text, mix_text);
            
            RoundKeys(mix_text, No_of_Expanded_keys[k].keys, encrypt_msg);
 
        }
    }
    
    for(int j=0;j<count;j++){
   
        int c = j + 1;
        RoundKeys(counter[c], key, encrypt_msg);
        printf("Plain text : ");
          for(int i=0; i<16; i++){
           printf("%x",counter[c][i]);
        }
        printf("\n");
        printf("round0 enc_msg : ");
        for(int i=0; i<16; i++){
           printf("%02x",encrypt_msg[i]);
        }
        printf("\n");

        for(int k=1;k<11;k++) {
          if(k == 10) {
            Subbyte(encrypt_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);

            RoundKeys(shift_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("last round enc_msg : ");
            for(int i=0; i<16; i++){
                printf("%02x",encrypt_msg[i]);
            }
            printf("\n");
  
          }
          else {
            Subbyte(encrypt_msg, sub_text, 16);

            shiftrow(sub_text, shift_text);
            
            mixcolumn(shift_text, mix_text);
            
            RoundKeys(mix_text, No_of_Expanded_keys[k].keys, encrypt_msg);
            printf("round %d enc_msg : ",k);
            for(int i=0; i<16; i++){
                printf("%x",encrypt_msg[i]);
            }
            printf("\n");
        }
    }
    
    for(int i=0;i<16;i++) {
        encrypted_msg[j][i] = text[j][i] ^ encrypt_msg[i];
        printf("%02x", encrypted_msg[j][i]);
    }
    printf("\n");
}
    
    return 0;

}

void RoundKeys(uint8_t plain_message[], uint8_t cipher_key[], uint8_t encrypted_message[]) {
    for(uint8_t i=0; i<16; i++) {
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

  for(int i = 0; i < length; i++){
      row_num = (plain_text[i] & 0xF0) >> 4;
      col_num = plain_text[i] & 0x0F;
      transfered_text[i] = sbox[16*row_num + col_num];
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
            Subbyte(rotated_block, sub_block, 4);

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

void shiftrow(uint8_t *transfered_text, uint8_t *shifted_text)
{
      uint8_t temp[6];
      temp[0] = transfered_text[1];

      temp[1] = transfered_text[2];
      temp[2] = transfered_text[6];

      temp[3] = transfered_text[3];
      temp[4] = transfered_text[7];
      temp[5] = transfered_text[11];

      for(int i = 0; i<4; i++){
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
    for(int i = 0; i<4; i++){
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
    uint8_t incr = 0x00;
    
    for(int k=0;k<count+1;k++) {
        for(int i=0;i<16;i++) {
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
        
        printf("\n");
    }
}

int plaintext_block(uint8_t *plaintext, int text_length, int count) {
    
     int text_count = 0;
     
     while(text_length > 0) {
         if(text_length >= 16) {
           for(int i=0;i<16;i++) {
             text[count][i] = plaintext[text_count];
             text_count = text_count + 1;
           }
           text_length = text_length - text_count;
           count++;
         }
         else {
            int zero_pad = 16 - text_length;
            
            for(int i=0;i<text_length;i++) {
                text[count][i] = plaintext[text_count];
                text_count = text_count + 1;
            }
            
            for(int i=text_length-1;i<zero_pad;i++) {
                text[count][i] = 0x00;
                text_count = text_count + 1;
            }
            text_length = text_length - text_count;
            count++;
        }
    }
    
    return count;
    
}

* Multiplication in GF(2^128) */
static void gf_mult(const u8 *x, const u8 *y, u8 *z)
{
    
    for(int k=0;k<16;k++) {
       for(int i=0;i<8;i++) {
          if(x[i] | 0xFE) {
            z[i+1] = z[i] ^ (v[i] & 0x01)
            0x01 << 1
          }
       }
    }
	u8 v[16];
	int i, j;
	os_memset(z, 0, 16); /* Z_0 = 0^128 */
	os_memcpy(v, y, 16); /* V_0 = Y */
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}
			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}
