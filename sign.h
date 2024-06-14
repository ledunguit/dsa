//
// Created by Zed on 14/06/2024.
//

#ifndef DIGITALSIGNATURE_SIGN_H
#define DIGITALSIGNATURE_SIGN_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm> // Include for std::transform

enum class Format { PEM, DER };

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __attribute__((visibility("default")))
#endif
#endif

using namespace std;

#endif
