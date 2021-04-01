/**  
 *  Version 1.4
 *  Zachary Goldstein (zng8tb)
 *  University of Virginia - McIntire School of Commerce
 * 
**/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// Special thanks to Adrian, Martin, and John for the ideas
#define NAME "NicoCoin"
#define FUNDER "riko-san"
#define GENESIS "I don't think there are bad people.\n" \
                "I think good people do bad stuff sometimes, and that's bad.\n" \
                "But if you just do it once, that's a mistake.\n" \
                "And that's not bad. I think.\n" \
                "  - Marceline"
#define LEDGER "ledger.txt"
#define RSA_BITS 1024
#define ADDR_SIZE 16
#define MAX_FILENAME 31

char get_op(int ac, char *av[]) {
    if (ac < 2)
        return '-';
    
    if (strcmp(av[1], "name") == 0)
        return 'n';
    if (strcmp(av[1], "genesis") == 0)
        return 'g';
    if (strcmp(av[1], "generate") == 0)
        return 'G';
    if (strcmp(av[1], "address") == 0)
        return 'a';
    if (strcmp(av[1], "fund") == 0)
        return 'f';
    if (strcmp(av[1], "transfer") == 0)
        return 't';
    if (strcmp(av[1], "balance") == 0)
        return 'b';
    if (strcmp(av[1], "verify") == 0)
        return 'v';
    if (strcmp(av[1], "mine") == 0)
        return 'm';
    if (strcmp(av[1], "validate") == 0)
        return 'V';
    
    return '-';
}

unsigned char *SHA256_block_hash(const char *file) {
    char *plaintext;
    unsigned char *hash;
    int fd;
    struct stat plaintext_info;

    if ((fd = open(file, O_RDONLY)) < 0) {
        fprintf(stderr, "Unable to open %s for hashing\n", file);
        return NULL;
    }

    if (fstat(fd, &plaintext_info)) {
        fprintf(stderr, "Failed to fstat %s\n", file);
        close(fd);
        return NULL;
    }

    if ((plaintext = (char *) mmap(NULL, plaintext_info.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0)) < 0) {
        fprintf(stderr, "Failed to mmap %s\n", file);
        close(fd);
        return NULL;
    }

    hash = (unsigned char *) malloc(SHA256_DIGEST_LENGTH);

    SHA256_CTX c;

    if (!SHA256_Init(&c)) {
        fprintf(stderr, "Failed to initialize SHA-256\n");
        free(hash);
        close(fd);
        return NULL;
    }

    if (!SHA256_Update(&c, plaintext, plaintext_info.st_size)) {
        fprintf(stderr, "Failed to update SHA-256\n");
        free(hash);
        close(fd);
        return NULL;
    }
    
    if (!SHA256_Final(hash, &c)) {
        fprintf(stderr, "Failed to finalize SHA-256\n");
        close(fd);
        free(hash);
        return NULL;
    }

    munmap(plaintext, plaintext_info.st_size);
    close(fd);
    return hash;
}

// #1
void name() {
    fprintf(stdout, NAME);
    return;
}

// #2
void genesis() {
    int fd;
    if ((fd = open("block_0.txt", O_RDWR | O_TRUNC | O_CREAT, S_IRWXU)) < 0) {
        fprintf(stderr, "Unable to open/create block_0.txt\n");
        exit(-1);
    }
    dprintf(fd, "%s", GENESIS);
    close(fd);

    fprintf(stdout, "Genesis block created in 'block_0.txt'\n");
}

// #3
void generate(const char *file) {
    FILE *fp;
    RSA *keys;
    BIGNUM *bne, *e, *d, *n;
    char *pem_private, *pem_public;

    keys = RSA_new();
    bne = BN_new();

    if (!BN_set_word(bne, RSA_F4)) {
        fprintf(stderr, "BN_set_word failed.\n");
        goto free_data;
    }

    if (!RSA_generate_key_ex(keys, RSA_BITS, bne, NULL)) {
        fprintf(stderr, "RSA_generate_key failed.\n");
        goto free_data;
    }

    if (!(fp = fopen(file, "w+"))) {
        fprintf(stderr, "Unable to open/create %s\n", file);
        goto free_data;
    }

    if (!PEM_write_RSAPrivateKey(fp, keys, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key\n");
    }

    if (!PEM_write_RSAPublicKey(fp, keys)) {
        fprintf(stderr, "Failed to write public key\n");
    }

    fclose(fp);

    free_data:

    RSA_free(keys);
    BN_free(bne);
    CRYPTO_cleanup_all_ex_data();
    return;
}

// #4
char *address(const char *file) {
    int keylen;
    FILE *fp;
    RSA *pub_key;
    BIO *bio;
    char *pub_pem_key;
    char *buffer;

    if (!(fp = fopen(file, "r"))) {
        fprintf(stderr, "Unable to open/create %s\n", file);
        exit(-1);
    }

    if (!(pub_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL))) {
        fprintf(stderr, "Missing public key\n");
        fclose(fp);
        exit(-1);
    }

    bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPublicKey(bio, pub_key)) {
        fprintf(stderr, "Failed to load public key\n");
        RSA_free(pub_key);
        BIO_free_all(bio);
        exit(-1);
    }
    
    keylen = BIO_pending(bio);
    pub_pem_key = (char *) malloc(sizeof(char) * (keylen + 1));
    memset(pub_pem_key, 0, keylen + 1);
    BIO_read(bio, pub_pem_key, keylen);

    BIO_free_all(bio);
    RSA_free(pub_key);
    fclose(fp);

    SHA256_CTX c;
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

    if (!SHA256_Init(&c)) {
        fprintf(stderr, "Failed to initialize SHA-256\n");
        free(pub_pem_key);
        exit(-1);
    }

    if (!SHA256_Update(&c, pub_pem_key, keylen)) {
        fprintf(stderr, "Failed to update SHA-256\n");
        free(pub_pem_key);
        exit(-1);
    }
    
    if (!SHA256_Final(hash, &c)) {
        fprintf(stderr, "Failed to finalize SHA-256\n");
        free(pub_pem_key);
        exit(-1);
    }
    
    buffer = (char *) malloc(sizeof(char) * (ADDR_SIZE + 1));
    memset(buffer, 0, ADDR_SIZE + 1);
    int i;
    for (i = 0; i < ADDR_SIZE / 2; i += 1) {
        snprintf(buffer + (i * 2), 3, "%02x", hash[i]);
    }

    buffer[ADDR_SIZE] = '\0';
    free(pub_pem_key);
    return buffer;
}

// #5
void fund(const char *w_addr, char *amtv, const char *file) {
    int keylen;
    double amt;
    char *endptr, buffer[64];
    FILE *fp;
    time_t t_raw;
    struct tm *t;

    amt = strtod(amtv, &endptr);
    
    if (amt < 0) {
        fprintf(stdout, "Cannot transfer negative amounts\n");
        exit(-1);
    }

    if (errno == ERANGE) {
        fprintf(stderr, "Error in amount conversion");
        exit(-1);
    }

    if (!(fp = fopen(file, "w+"))) {
        fprintf(stderr, "Unable to open/create %s\n", file);
        exit(-1);
    }

    time(&t_raw);
    t = localtime(&t_raw);
    strftime(buffer, 64, "%a %b %d %H:%M:%S %Z %Y", t);

    fprintf(fp, "Src:  %s\n", FUNDER);
    fprintf(fp, "Dest: %s\n", w_addr);
    fprintf(fp, "Amt:  %.2f\n", amt);
    fprintf(fp, "Date: %s", buffer);

    fclose(fp);
}

// #6
void transfer(const char *w_file, const char *w_addr, char *amtv, const char *t_file) {
    // Part 1: Transaction details
    int keylen;
    double amt;
    char *endptr, buffer[64], *prv_pem_key, *result;
    FILE *fp_t;
    time_t t_raw;
    struct tm *t;

    amt = strtod(amtv, &endptr);
    
    if (amt < 0) {
        fprintf(stdout, "Cannot transfer negative amounts\n");
        exit(-1);
    }

    if (errno == ERANGE) {
        fprintf(stdout, "Error in amount conversion");
        exit(-1);
    }

    if (!(fp_t = fopen(t_file, "w+"))) {
        fprintf(stderr, "Unable to open/create %s\n", t_file);
        exit(-1);
    }

    time(&t_raw);
    t = localtime(&t_raw);
    strftime(buffer, 64, "%a %b %d %H:%M:%S %Z %Y", t);

    result = address(w_file);

    fprintf(fp_t, "Src:  %s\n", result);
    fprintf(fp_t, "Dest: %s\n", w_addr);
    fprintf(fp_t, "Amt:  %.2f\n", amt);
    fprintf(fp_t, "Date: %s", buffer);

    free(result);
    fclose(fp_t);

    // Part 2: Create signature
    int fd_t;
    FILE *fp_w;
    struct stat plaintext_info;
    EVP_PKEY *pkey;
    EVP_MD_CTX *sign_ctx;
    unsigned char *sig;
    char *plaintext;
    size_t siglen;
    RSA *prv_key;

    if (!(fp_w = fopen(w_file, "r"))) {
        fprintf(stderr, "Unable to open/create %s\n", w_file);
        exit(-1);
    }

    if (!(prv_key = PEM_read_RSAPrivateKey(fp_w, NULL, NULL, NULL))) {
        fprintf(stderr, "Missing private key\n");
        fclose(fp_w);
        exit(-1);
    }

    fclose(fp_w);

    if ((fd_t = open(t_file, O_RDONLY)) < 0) {
        fprintf(stderr, "Unable to reopen %s\n", t_file);
        RSA_free(prv_key);
        exit(-1);
    }

    if (fstat(fd_t, &plaintext_info)) {
        fprintf(stderr, "Failed to fstat %s\n", t_file);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    if ((plaintext = (char *) mmap(NULL, plaintext_info.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd_t, 0)) < 0) {
        fprintf(stderr, "Failed to mmap %s\n", t_file);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, prv_key)) {
        fprintf(stderr, "Failed to convert RSA to EVP\n");
        // EVP_PKEY_free(pkey);
        close(fd_t);
        RSA_free(prv_key);
        exit(-1);
    }

    sign_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, pkey)) {
        fprintf(stderr, "Failed to initialize signing digest\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(sign_ctx);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    if (!EVP_DigestSignUpdate(sign_ctx, plaintext, plaintext_info.st_size)) {
        fprintf(stderr, "Failed to update signing digest\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(sign_ctx);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    if ((siglen = EVP_PKEY_size(pkey)) == 0) {
        fprintf(stderr, "Invalid key length\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(sign_ctx);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    sig = (char *) malloc(EVP_PKEY_size(pkey));

    if (!EVP_DigestSignFinal(sign_ctx, sig, &siglen)) {
        fprintf(stderr, "Failed to finalize signing digest\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(sign_ctx);
        RSA_free(prv_key);
        close(fd_t);
        exit(-1);
    }

    munmap(plaintext, plaintext_info.st_size);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(sign_ctx);
    // RSA_free(prv_key);
    close(fd_t);

    if (!(fp_t = fopen(t_file, "a"))) {
        fprintf(stderr, "Unable to open/create %s\n", w_file);
        exit(-1);
    }

    fprintf(fp_t, "\n");

    int i;
    for (i = 0; i < siglen; i += 1) {
        fprintf(fp_t, "%02x", sig[i]);
    }

    free(sig);
    fclose(fp_t);
    EVP_cleanup();
    ERR_free_strings();
}

// #7
double balance(const char *addr) {
    double bal;
    int i;
    char file_buf[MAX_FILENAME + 1];
    FILE *fp;

    bal = 0;
    i = 1;

    memset(file_buf, 0, MAX_FILENAME + 1);
    memcpy(file_buf, "block_1.txt", 11);
    while ((fp = fopen(file_buf, "r")) != NULL) {
        fflush(stdout);
        ssize_t read;
        char *line, *next, *src, *dest, *amt, *endptr;
        size_t len;
        int skip;

        line = NULL;
        next = NULL;
        len = 0;
        skip = 1;
        while ((read = getline(&line, &len, fp)) >= 0) {
            if (skip) {
                skip = 0;
                continue;
            }

            if (read == 1)
                continue;

            src = strtok_r(line, " ", &next);
            strtok_r(next, " ", &next);
            amt = strtok_r(next, " ", &next);
            strtok_r(next, " ", &next);
            dest = strtok_r(next, " ", &next);

            if (strncmp(src, "Nonce: ", strlen("Nonce")) == 0) {
                break;
            }

            if (strcmp(src, addr) == 0) {
                bal -= strtod(amt, &endptr);
            }
            if (strcmp(dest,addr) == 0) {
                bal += strtod(amt, &endptr);
            }
        }

        free(line);
        fclose(fp);

        i += 1;
        sprintf(file_buf + 6, "%d", i);
        memcpy(file_buf + strlen(file_buf), ".txt", 4);
    }

    if ((fp = fopen(LEDGER, "r")) != NULL) {;
        ssize_t read;
        char *line, *next, *src, *dest, *amt, *endptr;
        size_t len;

        line = NULL;
        next = NULL;
        len = 0;

        while ((read = getline(&line, &len, fp)) >= 0) {
            if (read == 1)
                continue;

            src = strtok_r(line, " ", &next);
            strtok_r(next, " ", &next);
            amt = strtok_r(next, " ", &next);
            strtok_r(next, " ", &next);
            dest = strtok_r(next, " ", &next);

            if (strncmp(src, addr, ADDR_SIZE) == 0) {
                bal -= strtod(amt, &endptr);
            }
            if (strncmp(dest, addr, ADDR_SIZE) == 0) {
                bal += strtod(amt, &endptr);
            }
        }

        free(line);
        fclose(fp);
    }
    return bal;
}

// #8
void verify(const char *w_file, const char *t_file) {
    // Part 1: Extract transaction info
    FILE *fp_t;
    int fd_t, sz, newline_n, f;
    char *plaintext;
    struct stat plaintext_info;

    if ((fd_t = open(t_file, O_RDONLY)) < 0) {
        fprintf(stderr, "Unable to open %s\n", t_file);
        exit(-1);
    }

    if (fstat(fd_t, &plaintext_info)) {
        fprintf(stderr, "Failed to fstat %s\n", t_file);
        close(fd_t);
        exit(-1);
    }

    if ((plaintext = (char *) mmap(NULL, plaintext_info.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd_t, 0)) < 0) {
        fprintf(stderr, "Failed to mmap %s\n", t_file);
        close(fd_t);
        exit(-1);
    }

    f = 0;

    if (strncmp(plaintext + 6, FUNDER, strlen(FUNDER)) == 0) {
        f = 1;
        munmap(plaintext, plaintext_info.st_size);
        close(fd_t);
        goto skip_signature;
    }

    sz = 0;
    newline_n = 0;
    for (sz = 0; sz < plaintext_info.st_size; sz += 1) {
        if (plaintext[sz] == '\n')
            newline_n += 1;
        if (newline_n == 4) {
            plaintext[sz] == '\0';
            break;
        }
    }

    // Part 2: Verify signature
    unsigned char *sig;
    FILE *fp_w;
    EVP_PKEY *pkey;
    EVP_MD_CTX *verify_ctx;
    RSA *pub_key;
    size_t siglen;

    if (!(fp_w = fopen(w_file, "r"))) {
        fprintf(stderr, "Unable to open/create %s\n", w_file);
        exit(-1);
    }

    if (!(pub_key = PEM_read_RSAPublicKey(fp_w, NULL, NULL, NULL))) {
        fprintf(stderr, "Missing private key\n");
        fclose(fp_w);
        close(fd_t);
        exit(-1);
    }

    fclose(fp_w);

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, pub_key)) {
        fprintf(stderr, "Failed to convert RSA to EVP\n");
        // EVP_PKEY_free(pkey);
        close(fd_t);
        RSA_free(pub_key);
        exit(-1);
    }

    if ((siglen = EVP_PKEY_size(pkey)) == 0) {
        fprintf(stderr, "Invalid key length\n");
        close(fd_t);
        exit(-1);
    }

    sig = (unsigned  char *) malloc(sizeof(char) * siglen);
    memset(sig, 0, siglen);

    unsigned int u;

    int i;
    for (i = 0; i < (siglen * 2); i += 2) {
        sscanf(plaintext + sz + i + 1, "%2x", &u);
        sig[i / 2] = u;
    }

    verify_ctx = EVP_MD_CTX_new();

    if (!EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, pkey)) {
        fprintf(stderr, "Failed to initialize verification digest\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(verify_ctx);
        RSA_free(pub_key);
        close(fd_t);
        exit(-1);
    }

    if (!EVP_DigestVerifyUpdate(verify_ctx, plaintext, sz)) {
        fprintf(stderr, "Failed to update verification digest\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(verify_ctx);
        RSA_free(pub_key);
        close(fd_t);
        exit(-1);
    }

    int result;
    if ((result = EVP_DigestVerifyFinal(verify_ctx, sig, siglen)) < 0) {
        fprintf(stderr, "Failed to finalize verification digest (an error occured)\n");
        // EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(verify_ctx);
        RSA_free(pub_key);
        close(fd_t);
        exit(-1);
    }

    if (result == 0 && f == 0) {
        fprintf(stdout, "Signature incorrect\n");
        EVP_MD_CTX_destroy(verify_ctx);
        RSA_free(pub_key);
        close(fd_t);
        exit(-1);
    }

    EVP_MD_CTX_destroy(verify_ctx);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    free(sig);
    munmap(plaintext, plaintext_info.st_size);
    close(fd_t);

    // Part 3: Verify balance
    double bal, request;
    char *src, *dest, *amt, *date, *line, *endptr;
    ssize_t read;
    size_t len;

    skip_signature:

    if (!(fp_t = fopen(t_file, "r"))) {
        fprintf(stderr, "Unabled to re-open %s\n", t_file);
        exit(-1);
    }

    line = NULL;
    endptr = NULL;
    len = 0;

    read = getline(&line, &len, fp_t);
    if (line[read - 1] == '\n')
        line[read - 1] = '\0';
    src = (char *) malloc(sizeof(char) * (read + 1));
    memset(src, 0, read + 1);
    memcpy(src, line, read);
    
    read = getline(&line, &len, fp_t);
    if (line[read - 1] == '\n')
        line[read - 1] = '\0';
    dest = (char *) malloc(sizeof(char) * (read + 1));
    memset(dest, 0, read + 1);
    memcpy(dest, line, read);

    read = getline(&line, &len, fp_t);
    if (line[read - 1] == '\n')
        line[read - 1] = '\0';
    amt = (char *) malloc(sizeof(char) * (read + 1));
    memset(amt, 0, read + 1);
    memcpy(amt, line, read);
    request = strtod(line + 5, &endptr);

    read = getline(&line, &len, fp_t);
    if (line[read - 1] == '\n')
        line[read - 1] = '\0';
    date = (char *) malloc(sizeof(char) * (read + 1));
    memset(date, 0, read + 1);
    memcpy(date, line, read);

    free(line);

    bal = balance(src + 6);

    fclose(fp_t);

    if (bal < request && f == 0) {
        fprintf(stderr, "Too few %ss (%.2f) to fulfill transaction request (%.2f)\n", NAME, bal, request);
        free(src);
        free(dest);
        free(amt);
        free(date);
        exit(-1);
    }

    // Part 4: Write to ledger
    FILE *fp_l;

    if (!(fp_l = fopen(LEDGER, "a"))) {
        fprintf(stderr, "Unable to open %s\n", LEDGER);
        free(src);
        free(dest);
        free(amt);
        free(date);
        exit(-1);
    }

    fprintf(fp_l, "%s transferred %s to %s on %s\n", src + 6, amt + 6, dest + 6, date + 6);

    if (!f)
        fprintf(stdout, "The transaction in file '%s' with wallet '%s' is valid, and was written to the ledger\n", t_file, w_file);
    else
        fprintf(stdout, "Any funding request (i.e. %s) is considered valid; written to ledger\n", FUNDER);


    free(src);
    free(dest);
    free(amt);
    free(date);
    fclose(fp_l);
}

// #9
void mine(int diff) {
    int i, match;
    char file_buf[MAX_FILENAME + 1], file_buf_next[MAX_FILENAME + 1], *block_buf, num_buf[32];
    unsigned char *hash_prev;
    FILE *fp_new, *fp_l;
    size_t block_len_prev, nonce;
    struct stat newblock_info;
    
    memset(file_buf, 0, MAX_FILENAME + 1);
    memset(file_buf_next, 0, MAX_FILENAME + 1);
    memcpy(file_buf, "block_0.txt", strlen("block_0.txt"));

    if (access(file_buf, F_OK | R_OK) < 0) {
        fprintf(stderr, "Missing %s (genesis_block)\n", file_buf);
        exit(-1);
    }

    i = 1;
    do {
        memcpy(file_buf, file_buf_next, strlen(file_buf_next));
        memcpy(file_buf_next, "block_", 6);
        sprintf(file_buf_next + 6, "%d", i);
        memcpy(file_buf_next + strlen(file_buf_next), ".txt", 4);
        i += 1;
    } while (access(file_buf_next, F_OK | R_OK) == 0);

    if (!(fp_new = fopen(file_buf_next, "w"))) {
        fprintf(stderr, "Unable to create %s\n", file_buf_next);
        exit(-1);
    }

    hash_prev = SHA256_block_hash(file_buf);
    
    for (i = 0; i < SHA256_DIGEST_LENGTH; i += 1) {
        fprintf(fp_new, "%02x", hash_prev[i]);
    }

    fprintf(fp_new, "\n");

    if (!(fp_l = fopen(LEDGER, "r"))) {
        fprintf(stderr, "WARNING: Mining without ledger\n");
    } else {
        char c;
        c = fgetc(fp_l);
        while (c != EOF) {
            fputc(c, fp_new);
            c = fgetc(fp_l);
        }
    }

    fclose(fp_l);
    fprintf(fp_new, "Nonce: ");
    fflush(fp_new);
    free(hash_prev);
    fclose(fp_new);

    // rewind wasn't working :(
    if (!(fp_new = fopen(file_buf_next, "r+")) < 0) {
        fprintf(stderr, "Unable to reopen %s\n", file_buf_next);
        exit(-1);
    }

    if (fstat(fileno(fp_new), &newblock_info)) {
        fprintf(stderr, "Failed to fstat %s\n", file_buf_next);
        fclose(fp_new);
        exit(-1);
    }

    block_buf = (char *) malloc(newblock_info.st_size + 32);
    memset(block_buf, 0, newblock_info.st_size + 32);
    fread(block_buf, 1, newblock_info.st_size, fp_new);

    nonce = 0;
    match = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH + 1];
    memset(hash, 0, SHA256_DIGEST_LENGTH + 1);

    do {
        sprintf(num_buf, "%ld", nonce);
        memcpy(block_buf + newblock_info.st_size, num_buf, strlen(num_buf));

        SHA256_CTX c;

        if (!SHA256_Init(&c)) {
            fprintf(stderr, "Failed to initialize SHA-256\n");
            free(block_buf);
            fclose(fp_new);
            exit(-1);
        }

        if (!SHA256_Update(&c, block_buf, newblock_info.st_size + strlen(num_buf))) {
            fprintf(stderr, "Failed to update SHA-256\n");
            free(block_buf);
            fclose(fp_new);
            exit(-1);
        }
        
        if (!SHA256_Final(hash, &c)) {
            fprintf(stderr, "Failed to finalize SHA-256\n");
            free(block_buf);
            fclose(fp_new);
            exit(-1);
        }

        nonce += 1;
        int d = 0;
        i = 0;
        // printf("diff: %d\n", diff);
        while (d < SHA256_DIGEST_LENGTH) {
            if (d >= diff) {
                match = 1;
                break;
            }
            
            if (hash[i] == 0) {
                d += 2;
                if (d >= diff) {
                    match = 1;
                    break;
                }
            } else if ((hash[i] & 0xF0) == 0) {
                d += 1;
                if (d >= diff) {
                    match = 1;
                    break;
                }
                break;
            } else {
                break;
            }

            if (d >= diff) {
                match = 1;
                break;
            }

            i += 1;
        }
        // for (i = 0; i < SHA256_DIGEST_LENGTH; i += 1) {
        //     fprintf(stdout, "%02x", hash[i]);
        // }
        // printf("\n");
        
    } while (!match);

    fclose(fp_new);

    if ((fp_new = fopen(file_buf_next, "w")) < 0) {
        fprintf(stderr, "Unable to open %s to write nonce\n", file_buf_next);
        free(block_buf);
        fclose(fp_new);
        exit(-1);
    }
    fprintf(fp_new, "%s", block_buf);
    free(block_buf);
    fclose(fp_new);
    truncate(LEDGER, 0);
}

// #10
void validate() {
    int fd_prev, fd_cur, i;
    SHA256_CTX c;
    unsigned char *hash;
    char file_prev_buf[MAX_FILENAME + 1], file_cur_buf[MAX_FILENAME + 1];
    char prev_hash[(SHA256_DIGEST_LENGTH * 2) + 1], cur_hash[(SHA256_DIGEST_LENGTH * 2) + 1];

    memset(file_prev_buf, 0, MAX_FILENAME + 1);
    memset(file_cur_buf, 0, MAX_FILENAME + 1);
    memset(prev_hash, 0, (SHA256_DIGEST_LENGTH * 2) + 1);
    memset(cur_hash, 0, (SHA256_DIGEST_LENGTH * 2) + 1);

    memcpy(file_prev_buf, "block_0.txt", strlen("block_0.txt"));
    memcpy(file_cur_buf, "block_1.txt", strlen("block_1.txt"));

    if ((fd_prev = open(file_prev_buf, O_RDONLY)) < 0) {
        fprintf(stderr, "Unable to open block_0.txt (genesis block)\n");
        exit(-1);
    }

    i = 1;

    while (access(file_cur_buf, F_OK | R_OK) == 0) {
        if ((fd_cur = open(file_cur_buf, O_RDONLY)) < 0) {
            fprintf(stderr, "Unable to open %s\n", file_cur_buf);
            close(fd_prev);
            exit(-1);
        }

        if (read(fd_cur, cur_hash, SHA256_DIGEST_LENGTH * 2) < SHA256_DIGEST_LENGTH * 2) {
            fprintf(stderr, "%s has too few bytes\n", file_cur_buf);
            close(fd_prev);
            close(fd_cur);
            exit(-1);
        }
        
        hash = SHA256_block_hash(file_prev_buf);
        
        int r;
        for (r = 0; r < SHA256_DIGEST_LENGTH; r += 1) {
            snprintf(prev_hash + (r * 2), 3, "%02x", hash[r]);
        }

        free(hash);

        prev_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

        if (strncmp(cur_hash, prev_hash, SHA256_DIGEST_LENGTH * 2) != 0) {
            fprintf(stdout, "The blockchain is not valid. %s failed\n", file_cur_buf);
            close(fd_prev);
            close(fd_cur);
            return;
        }

        close(fd_prev);
        fd_prev = fd_cur;
        
        i += 1;
        memcpy(file_prev_buf, file_cur_buf, strlen(file_cur_buf));
        memcpy(file_cur_buf, "block_", 6);
        sprintf(file_cur_buf + 6, "%d", i);
        memcpy(file_cur_buf + strlen(file_cur_buf), ".txt", 4);
    }

    close(fd_cur);
    fprintf(stdout, "The entire blockchain is valid\n");
}

int main(int argc, char *argv[]) {
    char c;

    c = get_op(argc, argv);
    switch(c) {
        // #1
        case 'n':
            fprintf(stdout, "%s\n", NAME);
            exit(0);
            break;
        // #2    
        case 'g':
            genesis();
            exit(0);
            break;
        // #3
        case 'G':
            if (argc < 3) {
                fprintf(stderr, "Too few arguments for generate\n");
                exit(-1);
            }
            generate(argv[2]);
            exit(0);
            break;
        // #4
        case 'a':
            if (argc < 3) {
                fprintf(stderr, "Too few arguments for address\n");
                exit(-1);
            }
            char *result;
            result = address(argv[2]);
            fprintf(stdout, "%s\n", result);
            free(result);
            exit(0);
            break;
        // #5
        case 'f':
            if (argc < 5) {
                fprintf(stderr, "Too few arguments for fund\n");
                exit(-1);
            }
            fund(argv[2], argv[3], argv[4]);
            exit(0);
            break;
        // #6
        case 't':
            if (argc < 6) {
                fprintf(stderr, "Too few arguments for transfer\n");
                exit(-1);
            }
            transfer(argv[2], argv[3], argv[4], argv[5]);
            exit(0);
            break;
        // #7
        case 'b':
            if (argc < 3) {
                fprintf(stderr, "Too few arguments for transfer\n");
                exit(-1);
            }
            fprintf(stdout, "%.2f\n", balance(argv[2]));
            exit(0);
            break;
        // #8
        case 'v':
            if (argc < 4) {
                fprintf(stderr, "Too few arguments for transfer\n");
                exit(-1);
            }
            verify(argv[2], argv[3]);
            exit(0);
            break;
        // #9
        case 'm':
            if (argc < 3) {
                fprintf(stderr, "Too few arguments for mine\n");
                exit(-1);
            }
            mine(atoi(argv[2]));
            exit(0);
            break;
        // #10
        case 'V':
            validate();
            exit(-1);
            break;
    }

    fprintf(stdout,
        "Unknown function: %s\n"
        "Options:\n"
        "    name                                     \n"
        "    genesis                                  \n"
        "    generate <wallet>                        \n"
        "    address <wallet>                         \n"
        "    fund <addr> <amt> <stmt>                 \n"
        "    transfer <wallet> <addr> <amt> <stmt>    \n"
        "    balance <addr>                           \n"
        "    verify <wallet> <stmt>                   \n"
        "    mine <difficulty>                        \n"
        "    validate                                 \n",
        argv[0]);

    return 0;
}
