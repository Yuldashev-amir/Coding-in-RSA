// encrypDecryp.c Encryption and Decryption structure in RSA algorithm (OpenSSL 3.0)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define RSA_KEY_SIZE 2048
#define SALT_SIZE 4

struct __attribute__((packed)) newStruct
{
	float oneVal;
	float secVal;
	float thVal;
	float foVal;
	uint8_t minVal;
	uint16_t valOne16;
    uint16_t valTwo16;
};

const uint8_t salt[SALT_SIZE] = {0x76, 0x48, 0x2F, 0xAE};

void generate_rsa_keys() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(!ctx)
    {
    	fprintf(stderr, "Error failed to create for context\n");
    	return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    FILE *pub = fopen("public.pem", "wb");
    FILE *priv = fopen("private.pem", "wb");

    PEM_write_PUBKEY(pub, pkey);
    PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL);

    fclose(pub);
    fclose(priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

int encrypt_data(struct newStruct *data, uint8_t *encrypted, size_t *enc_len) {
    FILE *pub_file = fopen("public.pem", "rb");
    if (!pub_file) {
        fprintf(stderr, "Error public.pem not found\n");
        return -1;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!pkey) {
        fprintf(stderr, "Error reading public key\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    uint8_t buffer[sizeof(struct newStruct) + SALT_SIZE];
    memcpy(buffer, salt, SALT_SIZE);
    memcpy(buffer + SALT_SIZE, data, sizeof(struct newStruct));

    EVP_PKEY_encrypt(ctx, NULL, enc_len, buffer, sizeof(buffer));
    EVP_PKEY_encrypt(ctx, encrypted, enc_len, buffer, sizeof(buffer));

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
}

int decrypt_data(uint8_t *encrypted, size_t enc_len, struct newStruct *output) {
    FILE *priv_file = fopen("private.pem", "rb");
    if (!priv_file) {
        fprintf(stderr, "Error: private.pem not found\n");
        return -1;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!pkey) {
        fprintf(stderr, "Error reading in private key\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    uint8_t buffer[sizeof(struct newStruct) + SALT_SIZE];
    size_t dec_len;
    EVP_PKEY_decrypt(ctx, NULL, &dec_len, encrypted, enc_len);
    EVP_PKEY_decrypt(ctx, buffer, &dec_len, encrypted, enc_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (dec_len > SALT_SIZE) {
        memcpy(output, buffer + SALT_SIZE, sizeof(struct newStruct));
        return 1;
    } else {
        fprintf(stderr, "Decryption error\n");
        return -1;
    }
}

int main() {
    generate_rsa_keys();

    struct newStruct data = {1.23, 4.56, 7.89, 0.12, 255, 1024};
    uint8_t encrypted[256];
    struct newStruct decrypted;
    size_t enc_len;

    if (encrypt_data(&data, encrypted, &enc_len) == 1) {
        printf("✅ Data encrypted successfully!(%zu byte)\n", enc_len);
    }

    if (decrypt_data(encrypted, enc_len, &decrypted) == 1) {
        printf("✅ Data successfully decrypted!\n");
        printf("oneVal: %.2f, secVal: %.2f, minVal: %d\n", decrypted.oneVal, decrypted.secVal, decrypted.minVal);
    }

    return 0;
}