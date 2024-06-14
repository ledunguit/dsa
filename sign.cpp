//
// Created by Zed on 14/06/2024.
//

#include "cstdio"
#include "sign.h"

bool signPdf(const char *chrprivateKeyPath, char *chrpdfPath, const char *chrsignaturePath) {
    std::string privateKeyPath(chrprivateKeyPath), pdfPath(chrpdfPath), signaturePath(chrsignaturePath);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read the private key from file using BIO
    BIO *keyBio = BIO_new_file(privateKeyPath.c_str(), "r");
    if (!keyBio) {
        std::cerr << "Error opening private key file." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
    BIO_free(keyBio);
    if (!privateKey) {
        std::cerr << "Error reading private key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Read the PDF file using BIO
    BIO *pdfBio = BIO_new_file(pdfPath.c_str(), "rb"); //all file types as binary
    if (!pdfBio) {
        std::cerr << "Error opening PDF file." << std::endl;
        EVP_PKEY_free(privateKey);
        return false;
    }
    // Convert to bytes
    std::vector<unsigned char> pdfContents;
    char buffer[2048];
    int bytesRead = 0;
    while ((bytesRead = BIO_read(pdfBio, buffer, sizeof(buffer))) > 0) {
        pdfContents.insert(pdfContents.end(), buffer, buffer + bytesRead);
    }
    BIO_free(pdfBio);

    if (bytesRead < 0) {
        std::cerr << "Error reading PDF file." << std::endl;
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Step 1: Hash the PDF (may revise using EVP_MD_CTX)
    std::cout << "Hashing the PDF" << std::endl;
    unsigned char hash[SHA256_DIGEST_LENGTH]; //Create a Buffer for the Hash
    SHA256(&pdfContents[0], pdfContents.size(), hash); //Compute the Hash of the pdf

    // Step 2: Initialize the signing context
    std::cout << "Signing the hash" << std::endl;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Error creating EVP_MD_CTX." << std::endl;
        EVP_PKEY_free(privateKey);
        return false;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privateKey) <= 0) {
        std::cerr << "Error initializing DigestSign." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }
    // Step 3: Update the signing context with the data (hash)
    if (EVP_DigestSignUpdate(mdctx, hash, SHA256_DIGEST_LENGTH) <= 0) {
        std::cerr << "Error updating DigestSign." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Step 4: Finalize the signature
    size_t signatureLen = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &signatureLen) <= 0) {
        std::cerr << "Error getting signature length." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    std::vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(mdctx, &signature[0], &signatureLen) <= 0) {
        std::cerr << "Error signing PDF." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    //Step 5: Write the signature to a file using BIO
    BIO *sigBio = BIO_new_file(signaturePath.c_str(), "wb");
    if (!sigBio) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }
    if (BIO_write(sigBio, &signature[0], signatureLen) != (int)signatureLen) {
        std::cerr << "Error writing signature to file." << std::endl;
        BIO_free(sigBio);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Handle the result
    std::cout << "Signature saved successfully to " << signaturePath << std::endl;

    BIO_free(sigBio);
    // Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <private key file> <PDF file> <signature output file>" << std::endl;
        return 1;
    }
    const char* privateKeyPath = argv[1];
    char* pdfPath = argv[2];
    const char* signaturePath = argv[3];
    if (signPdf(privateKeyPath, pdfPath, signaturePath)) {
        std::cout << "PDF signed successfully." << std::endl;
    } else {
        std::cout << "Failed to sign PDF." << std::endl;
    }
    return 0;
}