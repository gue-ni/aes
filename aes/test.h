#ifndef TEST_H__
#define TEST_H__


void test(void);

extern uint8_t PLAINTEXT[16];
extern uint8_t KEY_128_1[16];
extern uint8_t KEY_128_2[16];  
extern uint8_t KEY_256_1[32];
extern uint8_t KEY_256_2[32];  
extern uint8_t OUT_128_1[16]; 

extern uint8_t KEY[16];
extern uint8_t IV[16];
extern uint8_t CIPHER[32];
extern uint8_t PLAIN[32];



#endif /* TEST_H__ */