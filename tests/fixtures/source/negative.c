const char *not_a_call = "RSA_verify(inside a string)";

/* ECDH_compute_key(inside, a, comment); */

int RSA_sign(int type, const unsigned char *message);

#define NOT_EXPANDED(value) RSA_public_encrypt(value)

void ordinary_code(void) {
    int RSA_significant = 1;
    (void)RSA_significant;
}

