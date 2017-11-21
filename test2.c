#include <tomcrypt.h>

int main(int argc, char *argv[])
{
    printf("%s\n","hello");
    int err, hash_idx, prng_idx, res;
    unsigned long l1, l2;
    unsigned char pt[16], pt2[16], out[1024];
    rsa_key key;
    for (int i = 0; i < 10; i++)
    {
        pt[i]= (char) (i);
    }
    pt[10] = 0;
    for (int i = 0; i < 16; i++)
    {
        printf("%c ", pt[i]);
    }
    printf("\n");
    /* register prng/hash */
    if (register_prng(&sprng_desc) == -1)
    {
        printf("Error registering sprng");
        return EXIT_FAILURE;
    }
    /* register a math library (in this case TomsFastMath)*/
    ltc_mp = tfm_desc;
    printf("%s\n", ltc_mp.name);
    if (register_hash(&sha1_desc) == -1)
    {
        printf("Error registering sha1");
        return EXIT_FAILURE;
    }
    hash_idx = find_hash("sha1");
    prng_idx = find_prng("sprng");
    /* make an RSA-1024 key */
    if ((err = rsa_make_key(NULL,     /* PRNG state */
                            prng_idx, /* PRNG idx */
                            1024 / 8, /* 1024-bit key */
                            65537,    /* we like e=65537 */
                            &key)     /* where to store the key */
         ) != CRYPT_OK)
    {
        printf("rsa_make_key %s", error_to_string(err));
        return EXIT_FAILURE;
    }
    /* fill in pt[] with a key we want to send ... */
    l1 = sizeof(out);
    if ((err = rsa_encrypt_key(pt,        /* data we wish to encrypt */
                               16,        /* data is 16 bytes long */
                               out,       /* where to store ciphertext */
                               &l1,       /* length of ciphertext */
                               "TestApp", /* our lparam for this program */
                               7,         /* lparam is 7 bytes long */
                               NULL,      /* PRNG state */
                               prng_idx,  /* prng idx */
                               hash_idx,  /* hash idx */
                               &key)      /* our RSA key */
         ) != CRYPT_OK)
    {
        printf("rsa_encrypt_key %s", error_to_string(err));
        return EXIT_FAILURE;
    }
    /* now let's decrypt the encrypted key */
    l2 = sizeof(pt2);
    if ((err = rsa_decrypt_key(out,       /* encrypted data */
                               l1,        /* length of ciphertext */
                               pt2,       /* where to put plaintext */
                               &l2,       /* plaintext length */
                               "TestApp", /* lparam for this program */
                               7,         /* lparam is 7 bytes long */
                               hash_idx,  /* hash idx */
                               &res,      /* validity of data */
                               &key)      /* our RSA key */
         ) != CRYPT_OK)
    {
        printf("rsa_decrypt_key %s", error_to_string(err));
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 16; i++)
    {
        printf("%c ", pt2[i]);
    }
    printf("\n");
    /* if all went well pt == pt2, l2 == 16, res == 1 */
}
