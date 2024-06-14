#include <cstdio>
#include "DSA.h"

extern "C" {
    DLL_EXPORT void generate_ecc_key(const char* curveName, Format format, const char* saveFileName);
    DLL_EXPORT void generate_rsa_key(int key_length, Format format, const char* saveFileName);
}

void write_key_to_file(EVP_PKEY* pkey, Format  format, const char* saveFileName, bool isPrivateKey) {
    string saveFileNameStr(saveFileName);

    if (isPrivateKey) {
        saveFileNameStr += ".key";
    } else {
        saveFileNameStr += ".pub";
    }

    string fileName = saveFileNameStr + (format == Format::PEM ? ".pem" : ".der");

    BIO* bio = BIO_new_file(fileName.c_str(), format == Format::PEM ? "w" : "wb");

    if (!bio) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (format == Format::PEM) {
        if (isPrivateKey) {
            if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        } else {
            if (!PEM_write_bio_PUBKEY(bio, pkey)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }
    } else {
        if (isPrivateKey) {
            if (i2d_PrivateKey_bio(bio, pkey) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        } else {
            if (i2d_PUBKEY_bio(bio, pkey) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }
    }

    BIO_free(bio);
}

void generate_random_exponent(BIGNUM* bn, int bits) {
    if (!BN_rand(bn, bits, 1, 1)) { // Generate a random number with 'bits' length, and enforce odd number
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void generate_rsa_key(int key_length, Format format, const char* saveFileName) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!pctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, key_length) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

//    // Generate a random large exponent
//    BIGNUM* bn = BN_new();
//    if (!bn) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    generate_random_exponent(bn, 256); // Generate a random 256-bit exponent
//
//    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(pctx, bn) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//    BN_free(bn);

    EVP_PKEY* pkey = EVP_PKEY_new();

    if (!pkey) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    write_key_to_file(pkey, format, saveFileName, true);
    write_key_to_file(pkey, format, saveFileName, false);

    std::cout << "Private key saved to " << saveFileName << ".key" << std::endl;
    std::cout << "Public key saved to " << saveFileName << ".pub" << std::endl;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

void generate_ecc_key(const char* curveName, Format format, const char* saveFileName) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (!pctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int nid = OBJ_sn2nid(curveName); // example: NID_X9_62_prime256v1

    if (nid == NID_undef) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* pkey = EVP_PKEY_new();

    if (!pkey) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    write_key_to_file(pkey, format, saveFileName, true);
    write_key_to_file(pkey, format, saveFileName, false);

    std::cout << "Private key saved to " << saveFileName << ".key" << std::endl;
    std::cout << "Public key saved to " << saveFileName << ".pub" << std::endl;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}

void str_to_lower(std::string& str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <key_type> <key_length_or_curve> <format> <key_name>" << std::endl;
        std::cerr << "    key_type: rsa or ecc" << std::endl;
        std::cerr << "    key_length_or_curve: prime256v1, secp384r1, secp521r1" << std::endl;
        std::cerr << "    format: pem or der" << std::endl;
        std::cerr << "    key_name: name of the key without extension" << std::endl;

        return EXIT_FAILURE;
    }

    const char* keyType = argv[1];
    const char* keyLengthOrCurve = argv[2];
    const char* formatInput = argv[3];
    const char* keyName = argv[4];

    Format format;

    if (std::string(formatInput) == "pem") {
        format = Format::PEM;
    } else if (std::string(formatInput) == "der") {
        format = Format::DER;
    } else {
        std::cerr << "Invalid format, <format> must be pem or der" << std::endl;
        return EXIT_FAILURE;
    }

    if (std::string(keyType) == "rsa") {
        int keyLength = stoi(keyLengthOrCurve);

        if (keyLength < 0) {
            std::cerr << "Invalid key length, key length must be positive" << std::endl;
            return EXIT_FAILURE;
        }

        generate_rsa_key(keyLength, format, keyName);
    } else if (std::string(keyType) == "ecc") {
        generate_ecc_key(keyLengthOrCurve, format, keyName);
    } else {
        std::cerr << "Invalid key type, <key_type> must be rsa or ecc" << std::endl;
        return EXIT_FAILURE;
    }

    return 0;
}
