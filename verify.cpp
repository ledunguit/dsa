#include "verify.h"

bool verifySignature(const std::string& publicKeyPath, const std::string& pdfPath, const std::string& signaturePath) {
    // Load the public key (PEM) using BIO
    BIO *pubData = BIO_new_file(publicKeyPath.c_str(), "r");
    if (!pubData) {
        std::cerr << "Error opening public key file." << std::endl;
        return false;
    }
    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(pubData, NULL, NULL, NULL);
    BIO_free(pubData);

    if (!publicKey) {
        std::cerr << "Error loading public key." << std::endl;
        return false;
    }

    // Load the PDF using BIO
    BIO *pdfBio = BIO_new_file(pdfPath.c_str(), "rb");
    if (!pdfBio) {
        std::cerr << "Error opening PDF file." << std::endl;
        EVP_PKEY_free(publicKey);
        return false;
    }
    std::vector<unsigned char> pdfContents;
    char buffer[1024];
    int bytesRead = 0;
    while ((bytesRead = BIO_read(pdfBio, buffer, sizeof(buffer))) > 0) {
        pdfContents.insert(pdfContents.end(), buffer, buffer + bytesRead);
    }
    BIO_free(pdfBio);
    if (bytesRead < 0) {
        std::cerr << "Error reading PDF file." << std::endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    // Create a buffer to hold the document hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&pdfContents[0], pdfContents.size(), hash);

    // Load the signature using BIO
    BIO *sigBio = BIO_new_file(signaturePath.c_str(), "rb");
    if (!sigBio) {
        std::cerr << "Error opening signature file." << std::endl;
        EVP_PKEY_free(publicKey);
        return false;
    }
    std::vector<unsigned char> signature;
    while ((bytesRead = BIO_read(sigBio, buffer, sizeof(buffer))) > 0) {
        signature.insert(signature.end(), buffer, buffer + bytesRead);
    }
    BIO_free(sigBio);
    if (bytesRead < 0) {
        std::cerr << "Error reading signature file." << std::endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    // Verify the signature
    EVP_MD_CTX *mesData = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mesData, NULL, EVP_sha256(), NULL, publicKey) <= 0) {
        std::cerr << "Error initializing DigestVerify." << std::endl;
        EVP_MD_CTX_free(mesData);
        EVP_PKEY_free(publicKey);
        return false;
    }
    if (EVP_DigestVerifyUpdate(mesData, hash, SHA256_DIGEST_LENGTH) <= 0) {
        std::cerr << "Error updating DigestVerify." << std::endl;
        EVP_MD_CTX_free(mesData);
        EVP_PKEY_free(publicKey);
        return false;
    }
    int result = EVP_DigestVerifyFinal(mesData, signature.data(), signature.size());

    // Clean up
    EVP_MD_CTX_free(mesData);
    EVP_PKEY_free(publicKey);

    if (result == 1) {
        std::cout << "PDF verified successfully." << std::endl;
        return true;
    } else if (result == 0) {
        std::cout << "Signature verification failed." << std::endl;
    } else {
        std::cerr << "Error during signature verification." << std::endl;
    }

    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public key file> <PDF file> <signature file>" << std::endl;
        return EXIT_FAILURE;
    }
    const std::string publicKeyPath = argv[1];
    const std::string pdfPath = argv[2];
    const std::string signaturePath = argv[3];
    if (verifySignature(publicKeyPath, pdfPath, signaturePath)) {
        std::cout << "PDF verified the pdf and signature successfully." << std::endl;
    } else {
        std::cout << "Failed to verify PDF." << std::endl;
    }
    return EXIT_SUCCESS;
}