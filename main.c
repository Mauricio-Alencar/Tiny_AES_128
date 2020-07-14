#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include "pkcs7_padding.h"

#define CBC 1
#define CTR 0
#define ECB 0

int hex_to_int(char c){
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

void hexString2ascii(char* hex_str)
{
	int length = strlen(hex_str);
    int i = 0;
    char buf = 0;
    for(i = 0; i < length; i++){
            if(i % 2 != 0){
                    printf("%c", hex_to_ascii(buf, hex_str[i]));
            }else{
                    buf = hex_str[i];
            }
    }
}

void string2hexString(char* input, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

uint8_t strChar2hex(char* str)
{
    int aux=0, aux2=0;

    if( (*str>='0') && (*str<='9') )
    {
        aux=*str++-'0';
    }
    else if( (*str>='A') && (*str<='F') )
    {
        aux=*str++-'A'+10;
    }
    else if( (*str>='a') && (*str<='f') )
    {
        aux=*str++-'a'+10;
    }
    if( (*str>='0') && (*str<='9') )
    {
        aux2=*str-'0';
    }
    else if( (*str>='A') && (*str<='F') )
    {
        aux2=*str-'A'+10;
    }
    else if( (*str>='a') && (*str<='f') )
    {
        aux2=*str-'a'+10;
    }
    return aux*16+aux2;
}

uint16_t str2hexByteArray(char* str, uint8_t* array)
{		
    // get length in bytes (half of ASCII characters)
	uint16_t length=strlen(str)/2;
	
	uint16_t j=0;
	
    // Conversion from ASCII to HEX    
    for(j=0; j<length; j++)
    {    
		array[j] = strChar2hex(&str[j*2]);      
    }
	
	return length;
}

uint16_t str2hexByteArray_with_SizeByteArray(char* str, uint8_t* array, uint16_t size)
{		
    // get length in bytes (half of ASCII characters)
	uint16_t length = strlen(str)/2;	
	uint16_t j = 0;
	
    // Conversion from ASCII to HEX    
    for(j=0; j<length; j++)
    {    
		// check size of array
		if (j >= size)
		{
			length = j;
			break;
		}
		
		// store conversion in array
		array[j] = strChar2hex(&str[j*2]);		     
    }
	
	return length;
}

void bytearray_to_hexstring(char * hex_string, char * byte_array, uint8_t hex_string_size)
{
    char hex_tab[16] = {'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F', };

    unsigned char byte;
    uint8_t i = 0;
    for(i = 0; i < (hex_string_size/2); i++)
    {
        byte = *byte_array++;
        *hex_string++ = hex_tab[byte >> 4];
        *hex_string++ = hex_tab[byte & 0xf];
    }
}

static void test_encrypt_cbc(void)
{
    //Initialization Vector
    uint8_t iv[]  = { 0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21 };

    uint8_t i;                               
    char* report = "hello";
    char* key = "thisIstheKey";
    int dlen = strlen(report);
    int klen = strlen(key);
    
    printf("THE PLAIN TEXT STRING = ");
    for (i=0; i<dlen;i++){
        printf("%c", report[i]);
    }
    printf("\n");
    
   
    //Proper Length of report
    int dlenu = dlen;
    if (dlen % 16) {
        dlenu += 16 - (dlen % 16);
        printf("Tamanho original da STRING = %d e o tamanho da STRING aos sofrer o padding = %d\n", dlen, dlenu);
    }
    
    //Proper length of key
    int klenu = klen;
    if (klen % 16) {
        klenu += 16 - (klen % 16);
        printf("tamanho original da KEY = %d e tamanho original da KEY ao sofrer padding = %d\n", klen, klenu);
    }
    
    // Make the uint8_t arrays
    uint8_t hexarray[dlenu];
    uint8_t kexarray[klenu];
    
    // Initialize them with zeros
    memset( hexarray, 0, dlenu );
    memset( kexarray, 0, klenu );
    
    // Fill the uint8_t arrays
    for (i=0;i<dlen;i++) {
        hexarray[i] = (uint8_t)report[i];
    }
    for (i=0;i<klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }                           
  
    int reportPad = pkcs7_padding_pad_buffer( hexarray, dlen, sizeof(hexarray), 16 );
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );
    
    printf("A STRING apos padding em hex = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");
    
    printf("A KEY apos o padding em hex = ");
    for (i=0; i<klenu;i++){
        printf("%02x",kexarray[i]);
    }
    printf("\n");
        
    // In case you want to check if the padding is valid
    int valid = pkcs7_padding_valid( hexarray, dlen, sizeof(hexarray), 16 );
    int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), 16 );
    printf("Validando pkcs7 padding, report = %d  |  key = %d\n", valid, valid2);
    
    //start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);
    
    // encrypt
    AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);
    printf("A STRING encryptada = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");
        
    // reset the iv !! important to work!
    AES_ctx_set_iv(&ctx,iv);
    
    // start decryption
    AES_CBC_decrypt_buffer(&ctx, hexarray, dlenu);
    
    size_t actualDataLength = pkcs7_padding_data_length( hexarray, dlenu, 16);
    printf("Tamanho da string decryptada sem padding = %ld\n", actualDataLength);
    
    printf("A string decryptada em hex = ");
    for (i=0; i<actualDataLength;i++){
        printf("%02x",hexarray[i]);
    }
    
    printf("\n");
    
    printf("A string decryptada em ASCII CHAR = ");
    for (i=0; i<actualDataLength;i++){
        printf("%c",hexarray[i]);
    }
    printf("\n");
}

uint32_t bufflen_to_padd(char * buffer_encrypt)
{
		int i = 0;
		int dlen = strlen(buffer_encrypt);
	    //int klen = strlen(key);
		
	    printf("THE PLAIN TEXT STRING = ");
	    for (i=0; i<dlen;i++){
	        printf("%c", buffer_encrypt[i]);
	    }
	    printf("\n");


	    //Proper Length of report
	    int dlenu = dlen;
	    if (dlen % 16) {
	        dlenu += 16 - (dlen % 16);
	        printf("Tamanho original da STRING = %d e o tamanho da STRING aos sofrer o padding = %d\n", dlen, dlenu);
	    }
		
		/*
	    //Proper length of key
	    int klenu = klen;
	    if (klen % 16) {
	        klenu += 16 - (klen % 16);
	        printf("tamanho original da KEY = %d e tamanho original da KEY ao sofrer padding = %d\n", klen, klenu);
	    }*/
	    
	    return dlenu;
}

uint8_t encrypt_buffer(uint8_t * buffer_encrypt, uint32_t buff_len, uint8_t * key, uint32_t key_len, uint8_t * iv, uint8_t * hexarray)
{
    uint8_t i;
	/*
    // Make the uint8_t arrays
    uint8_t hexarray[dlenu];
    uint8_t kexarray[klenu];

    // Initialize them with zeros
    memset( hexarray, 0, dlenu );
    memset( kexarray, 0, klenu );

    // Fill the uint8_t arrays
    for (i=0;i<dlen;i++) {
        hexarray[i] = (uint8_t)report[i];
    }
    for (i=0;i<klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }
	*/
	/*
	//cryptografia começa agora, antes foi somente preparando buffer para padding
    int reportPad = pkcs7_padding_pad_buffer( hexarray, dlen, sizeof(hexarray), 16 );
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );

    printf("A STRING apos padding em hex = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");

    printf("A KEY apos o padding em hex = ");
    for (i=0; i<klenu;i++){
        printf("%02x",kexarray[i]);
    }
    printf("\n");

    // In case you want to check if the padding is valid
    int valid = pkcs7_padding_valid( hexarray, dlen, sizeof(hexarray), 16 );
    int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), 16 );
    printf("Validando pkcs7 padding, report = %d  |  key = %d\n", valid, valid2);

    //start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);

    // encrypt
    AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);
    printf("A STRING encryptada = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");
    
    */
}

void encrypt_cbc(uint8_t * report, uint8_t * key, uint8_t * iv, uint8_t * hexbuffer)
{
    //Initialization Vector
    //uint8_t iv[]  = { 0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21 };

    uint8_t i;                               
    //char* report = "hello";
    //char* key = "thisIstheKey";
    int dlen = strlen(report);
    int klen = strlen(key);
    
    printf("THE PLAIN TEXT STRING = ");
    for (i=0; i<dlen;i++){
        printf("%c", report[i]);
    }
    printf("\n");
    
   
    //Proper Length of report
    int dlenu = dlen;
    if (dlen % 16) {
        dlenu += 16 - (dlen % 16);
        printf("Tamanho original da STRING = %d e o tamanho da STRING aos sofrer o padding = %d\n", dlen, dlenu);
    }
    
    //Proper length of key
    int klenu = klen;
    if (klen % 16) {
        klenu += 16 - (klen % 16);
        printf("tamanho original da KEY = %d e tamanho original da KEY ao sofrer padding = %d\n", klen, klenu);
    }
    
    // Make the uint8_t arrays
    uint8_t hexarray[dlenu];
    uint8_t kexarray[klenu];
    
    // Initialize them with zeros
    memset( hexarray, 0, dlenu);
    memset( kexarray, 0, klenu );
    
    // Fill the uint8_t arrays
    for (i=0;i<dlen;i++) {
        hexarray[i] = (uint8_t)report[i];
    }
    for (i=0;i<klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }                           
  
    int reportPad = pkcs7_padding_pad_buffer( hexarray, dlen, sizeof(hexarray), 16 );
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );
    
    printf("A STRING apos padding em hex = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");
    
    printf("A KEY apos o padding em hex = ");
    for (i=0; i<klenu;i++){
        printf("%02x",kexarray[i]);
    }
    
    printf("\n");
    uint8_t hexlen = strlen(hexbuffer); 
	printf("hexbuff len = %d\n", hexlen);
	
    // In case you want to check if the padding is valid
    int valid = pkcs7_padding_valid( hexarray, dlen, sizeof(hexarray), 16 );
    int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), 16 );
    printf("Validando pkcs7 padding, report = %d  |  key = %d\n", valid, valid2);
    
    //start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);
    
    // encrypt
    AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);
    
    memcpy(hexbuffer,hexarray, dlenu);
    
    printf("hexbuff len = %d\n", hexlen);
    
    printf("A STRING encryptada = ");
    for (i=0; i<dlenu;i++){
        printf("%02x",hexarray[i]);
    }
    printf("\n");
        
    // reset the iv !! important to work!
    AES_ctx_set_iv(&ctx,iv);
    
    // start decryption
    AES_CBC_decrypt_buffer(&ctx, hexarray, dlenu);
    
    size_t actualDataLength = pkcs7_padding_data_length( hexarray, dlenu, 16);
    printf("Tamanho da string decryptada sem padding = %ld\n", actualDataLength);
    
    printf("A string decryptada em hex = ");
    for (i=0; i<actualDataLength;i++){
        printf("%02x",hexarray[i]);
    }
    
    printf("\n");
    
    printf("A string decryptada em ASCII CHAR = ");
    for (i=0; i<actualDataLength;i++){
        printf("%c",hexarray[i]);
    }
    printf("\n");
}

void decrypt_cbc(uint8_t * report, uint32_t len_report, uint8_t * key, uint8_t * iv, uint8_t * hexbuffer)
{
    uint8_t i;                             
    uint32_t dlen;
    
    if(len_report == 0)
    {
    	dlen = strlen(report) - 1;
	}else
	{
		dlen = len_report;
	}
	
    uint8_t klen = strlen(key);
    uint8_t klenu = bufflen_to_padd(key);
    
    printf("len buff: %d\n", dlen);
	printf("key buff: %d\n", klen);
	
	uint8_t kexarray[klenu];
	memset( kexarray, 0, klenu );
	
	for (i=0;i<klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }
    
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );
    
    //start the struct
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);
    
    // start decryption
    AES_CBC_decrypt_buffer(&ctx, report, dlen);
    
    size_t actualDataLength = pkcs7_padding_data_length( report, dlen, 16);
    printf("Tamanho da string decryptada sem padding = %ld\n", actualDataLength);
    
    printf("A string decryptada em hex = ");
    for (i=0; i<actualDataLength;i++){
    	hexbuffer[i] = (uint8_t) report[i];
        printf("%02x",report[i]);
    }
    
    printf("\n");
    
    printf("A string decryptada em ASCII CHAR = ");
    for (i=0; i<actualDataLength;i++){
        printf("%c",report[i]);
    }
    printf("\n");
}

int main(void){
	
	//uint8_t iv[]  = { 0x75, 0x52, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x21, 0x21 };
	uint8_t * iv  = "0123456789abcdef";
	uint8_t * key = "ThisIsKey";	
	uint8_t * ascii_str = "Hello";
    
    //formatando buffer e tamanho de buffer para cryptografia padrão pkcs7
    uint32_t buff_len_padd = bufflen_to_padd(ascii_str);
	printf("Padding buffer lenght: %d\n\n", buff_len_padd);
	uint8_t hexarray[buff_len_padd];
	uint8_t decrypt_array[buff_len_padd];
	memset( decrypt_array, 0, buff_len_padd );
    memset( hexarray, 0, buff_len_padd );
    
    int len = strlen(ascii_str);
	int i = 0;
	
    // Completing buffer to encrypt
    for (i=0;i<len;i++) {
        hexarray[i] = (uint8_t) ascii_str[i];
    }
    
    //printing buffer
    for (i=0;i<len;i++) {
        printf("%c",hexarray[i]);
    }
    printf("\n\n");
    
    memset( hexarray, 0, buff_len_padd );
    
    encrypt_cbc(ascii_str, key, iv, hexarray);    
    
    //printando o buffer encryptado
    printf("Buffer Encryptado: ");
    for(i = 0; i < buff_len_padd; i++)
    {
    	printf("%02x", hexarray[i]);
	}
	printf("\n\n");

	//inicio do decrypt
	decrypt_cbc(hexarray, 0, key, iv, decrypt_array);
	
	for(i = 0; i < buff_len_padd; i++)
    {
    	printf("%02x", decrypt_array[i]);
	}
    
	    
    return 0;
}
