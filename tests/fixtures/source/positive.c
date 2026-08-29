void collect_crypto_evidence(void *ctx, void *key, void *mechanism) {
    RSA_sign(1, 0, 0, 0, 0, key);
    EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, 0);
    EVP_PKEY_CTX_new_from_name(0, "ML-KEM-768", 0);
    EVP_PKEY_derive(ctx, 0, 0);
    ECDSA_do_sign(0, 0, key);
    C_GenerateKeyPair(ctx, mechanism, 0, 0, 0, 0, 0, 0);
}
