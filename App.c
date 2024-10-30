/*
*   Librairies
*/

#include <stdio.h>
#include <openssl/evp.h>



/*
*   Fetching Provider 
*/

OSSL_PROVIDER *rsa_provider = OSSL_PROVIDER_load(NULL, 'cipherprovider');
if (rsa_provider == NULL) {
    printf("Failed to load RSA Provider\n");
    exit(EXIT_FAILURE);
}
else{
    printf("Succesful")
}

