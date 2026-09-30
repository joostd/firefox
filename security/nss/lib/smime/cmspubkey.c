/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * CMS public key crypto
 */

#include "cmslocal.h"

#include "cert.h"
#include "keyhi.h"
#include "secasn1.h"
#include "secitem.h"
#include "secoid.h"
#include "pk11func.h"
#include "secerr.h"
#include "secder.h"
#include "prerr.h"
#include "sechash.h"

/* ====== RSA ======================================================================= */

/*
 * NSS_CMSUtil_EncryptSymKey_RSA - wrap a symmetric key with RSA
 *
 * this function takes a symmetric key and encrypts it using an RSA public key
 * according to PKCS#1 and RFC2633 (S/MIME)
 */
SECStatus
NSS_CMSUtil_EncryptSymKey_RSA(PLArenaPool *poolp, CERTCertificate *cert,
                              PK11SymKey *bulkkey,
                              SECItem *encKey)
{
    SECStatus rv;
    SECKEYPublicKey *publickey;

    publickey = CERT_ExtractPublicKey(cert);
    if (publickey == NULL)
        return SECFailure;

    rv = NSS_CMSUtil_EncryptSymKey_RSAPubKey(poolp, publickey, bulkkey, encKey);
    SECKEY_DestroyPublicKey(publickey);
    return rv;
}

SECStatus
NSS_CMSUtil_EncryptSymKey_RSAPubKey(PLArenaPool *poolp,
                                    SECKEYPublicKey *publickey,
                                    PK11SymKey *bulkkey, SECItem *encKey)
{
    SECStatus rv;
    int data_len;
    KeyType keyType;
    void *mark = NULL;

    mark = PORT_ArenaMark(poolp);
    if (!mark)
        goto loser;

    /* sanity check */
    keyType = SECKEY_GetPublicKeyType(publickey);
    PORT_Assert(keyType == rsaKey);
    if (keyType != rsaKey) {
        goto loser;
    }
    /* allocate memory for the encrypted key */
    data_len = SECKEY_PublicKeyStrength(publickey); /* block size (assumed to be > keylen) */
    encKey->data = (unsigned char *)PORT_ArenaAlloc(poolp, data_len);
    encKey->len = data_len;
    if (encKey->data == NULL)
        goto loser;

    /* encrypt the key now */
    rv = PK11_PubWrapSymKey(PK11_AlgtagToMechanism(SEC_OID_PKCS1_RSA_ENCRYPTION),
                            publickey, bulkkey, encKey);

    if (rv != SECSuccess)
        goto loser;

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    if (mark) {
        PORT_ArenaRelease(poolp, mark);
    }
    return SECFailure;
}

/*
 * NSS_CMSUtil_DecryptSymKey_RSA - unwrap a RSA-wrapped symmetric key
 *
 * this function takes an RSA-wrapped symmetric key and unwraps it, returning a symmetric
 * key handle. Please note that the actual unwrapped key data may not be allowed to leave
 * a hardware token...
 */
PK11SymKey *
NSS_CMSUtil_DecryptSymKey_RSA(SECKEYPrivateKey *privkey, SECItem *encKey, SECOidTag bulkalgtag)
{
    /* that's easy */
    CK_MECHANISM_TYPE target;
    PORT_Assert(bulkalgtag != SEC_OID_UNKNOWN);
    target = PK11_AlgtagToMechanism(bulkalgtag);
    if (bulkalgtag == SEC_OID_UNKNOWN || target == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        return NULL;
    }
    return PK11_PubUnwrapSymKey(privkey, encKey, target, CKA_DECRYPT, 0);
}

typedef struct RSA_OAEP_CMS_paramsStr RSA_OAEP_CMS_params;
struct RSA_OAEP_CMS_paramsStr {
    SECAlgorithmID *hashFunc;
    SECAlgorithmID *maskGenFunc;
    SECAlgorithmID *pSourceFunc;
};

SEC_ASN1_MKSUB(SECOID_AlgorithmIDTemplate)
SEC_ASN1_MKSUB(SEC_OctetStringTemplate)

static const SEC_ASN1Template seckey_PointerToAlgorithmIDTemplate[] = {
    { SEC_ASN1_POINTER | SEC_ASN1_XTRN, 0,
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) }
};

static const SEC_ASN1Template RSA_OAEP_CMS_paramsTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(RSA_OAEP_CMS_params) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT |
          SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(RSA_OAEP_CMS_params, hashFunc),
      seckey_PointerToAlgorithmIDTemplate },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT |
          SEC_ASN1_CONTEXT_SPECIFIC | 1,
      offsetof(RSA_OAEP_CMS_params, maskGenFunc),
      seckey_PointerToAlgorithmIDTemplate },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT |
          SEC_ASN1_CONTEXT_SPECIFIC | 2,
      offsetof(RSA_OAEP_CMS_params, pSourceFunc),
      seckey_PointerToAlgorithmIDTemplate },
    { 0 }
};

/*
 * NSS_CMSUtil_DecryptSymKey_RSA_OAEP - unwrap a RSA-wrapped symmetric key
 *
 * this function takes an RSA-OAEP-wrapped symmetric key and unwraps it, returning a symmetric
 * key handle. Please note that the actual unwrapped key data may not be allowed to leave
 * a hardware token...
 */
PK11SymKey *
NSS_CMSUtil_DecryptSymKey_RSA_OAEP(SECKEYPrivateKey *privkey, SECItem *parameters, SECItem *encKey, SECOidTag bulkalgtag)
{
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
    RSA_OAEP_CMS_params encoded_params;
    SECAlgorithmID mgf1hashAlg;
    SECOidTag mgfAlgtag, pSourcetag;
    SECItem encoding_params, params;
    PK11SymKey *bulkkey = NULL;
    SECStatus rv;

    CK_MECHANISM_TYPE target;
    PORT_Assert(bulkalgtag != SEC_OID_UNKNOWN);
    target = PK11_AlgtagToMechanism(bulkalgtag);
    if (bulkalgtag == SEC_OID_UNKNOWN || target == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        return NULL;
    }

    PORT_Memset(&encoded_params, 0, sizeof(RSA_OAEP_CMS_params));
    PORT_Memset(&mgf1hashAlg, 0, sizeof(SECAlgorithmID));
    PORT_Memset(&encoding_params, 0, sizeof(SECItem));

    /* Set default values for the OAEP parameters */
    oaep_params.hashAlg = CKM_SHA_1;
    oaep_params.mgf = CKG_MGF1_SHA1;
    oaep_params.source = CKZ_DATA_SPECIFIED;
    oaep_params.pSourceData = NULL;
    oaep_params.ulSourceDataLen = 0;

    if (parameters->len == 2) {
        /* For some reason SEC_ASN1DecodeItem cannot process parameters if it is an emtpy SEQUENCE */
        /* Just check that this is a properly encoded empty SEQUENCE */
        /* TODO: Investigate if there a better way to handle this as part of decoding. */
        if ((parameters->data[0] != 0x30) || (parameters->data[1] != 0)) {
            return NULL;
        }
    } else {
        rv = SEC_ASN1DecodeItem(NULL, &encoded_params, RSA_OAEP_CMS_paramsTemplate, parameters);
        if (rv != SECSuccess) {
            goto loser;
        }
        if (encoded_params.hashFunc != NULL) {
            oaep_params.hashAlg = PK11_AlgtagToMechanism(SECOID_GetAlgorithmTag(encoded_params.hashFunc));
        }
        if (encoded_params.maskGenFunc != NULL) {
            mgfAlgtag = SECOID_GetAlgorithmTag(encoded_params.maskGenFunc);
            if (mgfAlgtag != SEC_OID_PKCS1_MGF1) {
                /* MGF1 is the only supported mask generation function */
                goto loser;
            }
            /* The parameters field contains an AlgorithmIdentifier specifying the
             * hash function to use with MGF1.
             */
            rv = SEC_ASN1DecodeItem(NULL, &mgf1hashAlg, SEC_ASN1_GET(SECOID_AlgorithmIDTemplate),
                                    &encoded_params.maskGenFunc->parameters);
            if (rv != SECSuccess) {
                goto loser;
            }
            oaep_params.mgf = SEC_GetMgfTypeByOidTag(SECOID_GetAlgorithmTag(&mgf1hashAlg));
            if (!oaep_params.mgf) {
                goto loser;
            }
        }
        if (encoded_params.pSourceFunc != NULL) {
            pSourcetag = SECOID_GetAlgorithmTag(encoded_params.pSourceFunc);
            if (pSourcetag != SEC_OID_PKCS1_PSPECIFIED) {
                goto loser;
            }
            /* The encoding parameters (P) are provided as an OCTET STRING in the parameters field. */
            if (encoded_params.pSourceFunc->parameters.len != 0) {
                rv = SEC_ASN1DecodeItem(NULL, &encoding_params, SEC_ASN1_GET(SEC_OctetStringTemplate),
                                        &encoded_params.pSourceFunc->parameters);
                if (rv != SECSuccess) {
                    goto loser;
                }
                oaep_params.ulSourceDataLen = encoding_params.len;
                oaep_params.pSourceData = encoding_params.data;
            }
        }
    }
    params.type = siBuffer;
    params.data = (unsigned char *)&oaep_params;
    params.len = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
    bulkkey = PK11_PubUnwrapSymKeyWithMechanism(privkey, CKM_RSA_PKCS_OAEP, &params,
                                                encKey, target, CKA_DECRYPT, 0);

loser:
    PORT_Free(oaep_params.pSourceData);
    if (encoded_params.hashFunc) {
        SECOID_DestroyAlgorithmID(encoded_params.hashFunc, PR_TRUE);
    }
    if (encoded_params.maskGenFunc) {
        SECOID_DestroyAlgorithmID(encoded_params.maskGenFunc, PR_TRUE);
    }
    if (encoded_params.pSourceFunc) {
        SECOID_DestroyAlgorithmID(encoded_params.pSourceFunc, PR_TRUE);
    }
    SECOID_DestroyAlgorithmID(&mgf1hashAlg, PR_FALSE);
    return bulkkey;
}

/* ====== ESECDH (Ephemeral-Static Elliptic Curve Diffie-Hellman) =========== */

typedef struct ECC_CMS_SharedInfoStr ECC_CMS_SharedInfo;
struct ECC_CMS_SharedInfoStr {
    SECAlgorithmID *keyInfo; /* key-encryption algorithm */
    SECItem entityUInfo;     /* ukm */
    SECItem suppPubInfo;     /* length of KEK in bits as 32-bit number */
};

static const SEC_ASN1Template ECC_CMS_SharedInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(ECC_CMS_SharedInfo) },
    { SEC_ASN1_XTRN | SEC_ASN1_POINTER,
      offsetof(ECC_CMS_SharedInfo, keyInfo),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED |
          SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 0,
      offsetof(ECC_CMS_SharedInfo, entityUInfo),
      SEC_ASN1_SUB(SEC_OctetStringTemplate) },
    { SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED |
          SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 2,
      offsetof(ECC_CMS_SharedInfo, suppPubInfo),
      SEC_ASN1_SUB(SEC_OctetStringTemplate) },
    { 0 }
};

/* Inputs:
 *       keyInfo: key-encryption algorithm
 *       ukm: ukm field of KeyAgreeRecipientInfo
 *       KEKsize: length of KEK in bytes
 *
 * Output: DER encoded ECC-CMS-SharedInfo
 */
static SECItem *
Create_ECC_CMS_SharedInfo(PLArenaPool *poolp,
                          SECAlgorithmID *keyInfo, SECItem *ukm, unsigned int KEKsize)
{
    ECC_CMS_SharedInfo SI;
    unsigned char suppPubInfo[4] = { 0 };

    SI.keyInfo = keyInfo;
    SI.entityUInfo.type = ukm->type;
    SI.entityUInfo.data = ukm->data;
    SI.entityUInfo.len = ukm->len;

    SI.suppPubInfo.type = siBuffer;
    SI.suppPubInfo.data = suppPubInfo;
    SI.suppPubInfo.len = sizeof(suppPubInfo);

    if (KEKsize > 0x1FFFFFFF) { // ensure KEKsize * 8 fits in 4 bytes.
        return NULL;
    }
    KEKsize *= 8;
    suppPubInfo[0] = (KEKsize & 0xFF000000) >> 24;
    suppPubInfo[1] = (KEKsize & 0xFF0000) >> 16;
    suppPubInfo[2] = (KEKsize & 0xFF00) >> 8;
    suppPubInfo[3] = KEKsize & 0xFF;

    return SEC_ASN1EncodeItem(poolp, NULL, &SI, ECC_CMS_SharedInfoTemplate);
}

/* this will generate a key pair, compute the shared secret, */
/* derive a key and ukm for the keyEncAlg out of it, encrypt the bulk key with */
/* the keyEncAlg, set encKey, keyEncAlg, publicKey etc.
 * The ukm is optional per RFC 5753. Pass a NULL value to request an empty ukm.
 * Pass a SECItem with the size set to zero, to request allocating a random
 * ukm of a default size. Or provide an explicit ukm that was defined by the caller.
 */
SECStatus
NSS_CMSUtil_EncryptSymKey_ESECDH(PLArenaPool *poolp, CERTCertificate *cert,
                                 PK11SymKey *bulkkey, SECItem *encKey,
                                 PRBool genUkm, SECItem *ukm,
                                 SECAlgorithmID *keyEncAlg, SECItem *pubKey,
                                 void *wincx)
{
    SECOidTag certalgtag; /* the certificate's encryption algorithm */
    SECStatus rv;
    SECStatus err;
    PK11SymKey *kek;
    SECKEYPublicKey *publickey = NULL;
    SECKEYPublicKey *ourPubKey = NULL;
    SECKEYPrivateKey *ourPrivKey = NULL;
    unsigned int bulkkey_size, kek_size;
    SECAlgorithmID keyWrapAlg;
    SECOidTag keyEncAlgtag;
    SECItem keyWrapAlg_params, *keyEncAlg_params, *SharedInfo;
    CK_MECHANISM_TYPE keyDerivationType, keyWrapMech;
    CK_ULONG kdf;

    if (genUkm && (ukm->len != 0 || ukm->data != NULL)) {
        PORT_SetError(PR_INVALID_ARGUMENT_ERROR);
        return SECFailure;
    }

    certalgtag = SECOID_GetAlgorithmTag(&(cert->subjectPublicKeyInfo.algorithm));
    PORT_Assert(certalgtag == SEC_OID_ANSIX962_EC_PUBLIC_KEY);
    if (certalgtag != SEC_OID_ANSIX962_EC_PUBLIC_KEY) {
        return SECFailure;
    }

    /* Get the public key of the recipient. */
    publickey = CERT_ExtractPublicKey(cert);
    if (publickey == NULL)
        goto loser;

    ourPrivKey = SECKEY_CreateECPrivateKey(&publickey->u.ec.DEREncodedParams,
                                           &ourPubKey, wincx);
    if (!ourPrivKey || !ourPubKey) {
        goto loser;
    }

    rv = SECITEM_CopyItem(poolp, pubKey, &ourPubKey->u.ec.publicValue);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* pubKey will be encoded as a BIT STRING, so pubKey->len must be length in bits
     * rather than bytes */
    pubKey->len = pubKey->len * 8;

    SECKEY_DestroyPublicKey(ourPubKey); /* we only need the private key from now on */
    ourPubKey = NULL;

    bulkkey_size = PK11_GetKeyLength(bulkkey);
    if (bulkkey_size == 0) {
        goto loser;
    }

    /* Parameters are supposed to be absent for AES key wrap algorithms.
     * However, Microsoft Outlook cannot decrypt message unless
     * parameters field is NULL. */
    keyWrapAlg_params.len = 2;
    keyWrapAlg_params.data = (unsigned char *)PORT_ArenaAlloc(poolp, keyWrapAlg_params.len);
    if (keyWrapAlg_params.data == NULL)
        goto loser;

    keyWrapAlg_params.data[0] = SEC_ASN1_NULL;
    keyWrapAlg_params.data[1] = 0;

    /* RFC5753 specifies id-aes128-wrap as the mandatory to support algorithm.
     * So, use id-aes128-wrap unless bulkkey provides more than 128 bits of
     * security. If bulkkey provides more than 128 bits of security, use
     * the algorithms from KE Set 2 in RFC 6318. */

    /* TODO: NIST Special Publication SP 800-56A requires the use of
     * Cofactor ECDH. However, RFC 6318 specifies the use of
     * dhSinglePass-stdDH-sha256kdf-scheme or dhSinglePass-stdDH-sha384kdf-scheme
     * for Suite B. The reason for this is that all of the NIST recommended
     * prime curves in FIPS 186-3 (including the Suite B curves) have a cofactor
     * of 1, and so for these curves standard and cofactor ECDH are the same.
     * This code should really look at the key's parameters and choose cofactor
     * ECDH if the curve has a cofactor other than 1. */
    if ((PK11_GetMechanism(bulkkey) == CKM_AES_CBC) && (bulkkey_size > 16)) {
        rv = SECOID_SetAlgorithmID(poolp, &keyWrapAlg, SEC_OID_AES_256_KEY_WRAP, &keyWrapAlg_params);
        kek_size = 32;
        keyWrapMech = CKM_NSS_AES_KEY_WRAP;
        kdf = CKD_SHA384_KDF;
        keyEncAlgtag = SEC_OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME;
        keyDerivationType = CKM_ECDH1_DERIVE;
    } else {
        rv = SECOID_SetAlgorithmID(poolp, &keyWrapAlg, SEC_OID_AES_128_KEY_WRAP, &keyWrapAlg_params);
        kek_size = 16;
        keyWrapMech = CKM_NSS_AES_KEY_WRAP;
        kdf = CKD_SHA256_KDF;
        keyEncAlgtag = SEC_OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME;
        keyDerivationType = CKM_ECDH1_DERIVE;
    }
    if (rv != SECSuccess) {
        goto loser;
    }

    /* ukm is optional, but RFC 5753 says that originators SHOULD include the ukm.
     * I made ukm 64 bytes, since RFC 2631 states that UserKeyingMaterial must
     * contain 512 bits for Diffie-Hellman key agreement. */

    if (genUkm) {
        ukm->type = siBuffer;
        ukm->len = 64;
        ukm->data = (unsigned char *)PORT_ArenaAlloc(poolp, ukm->len);

        if (ukm->data == NULL) {
            goto loser;
        }
        rv = PK11_GenerateRandom(ukm->data, ukm->len);
        if (rv != SECSuccess) {
            goto loser;
        }
    }

    SharedInfo = Create_ECC_CMS_SharedInfo(poolp, &keyWrapAlg,
                                           ukm,
                                           kek_size);
    if (!SharedInfo) {
        goto loser;
    }

    /* Generate the KEK (key exchange key) according to RFC5753 which we use
     * to wrap the bulk encryption key. */
    kek = PK11_PubDeriveWithKDF(ourPrivKey, publickey, PR_TRUE,
                                NULL, NULL,
                                keyDerivationType, keyWrapMech,
                                CKA_WRAP, kek_size, kdf, SharedInfo, NULL);
    if (!kek) {
        goto loser;
    }

    SECKEY_DestroyPublicKey(publickey);
    SECKEY_DestroyPrivateKey(ourPrivKey);
    publickey = NULL;
    ourPrivKey = NULL;

    /* allocate space for the encrypted CEK (bulk key) */
    /* AES key wrap produces an output 64-bits longer than
     * the input AES CEK (RFC 3565, Section 2.3.2) */
    encKey->len = bulkkey_size + 8;
    encKey->data = (unsigned char *)PORT_ArenaAlloc(poolp, encKey->len);

    if (encKey->data == NULL) {
        PK11_FreeSymKey(kek);
        goto loser;
    }

    err = PK11_WrapSymKey(keyWrapMech, NULL, kek, bulkkey, encKey);

    PK11_FreeSymKey(kek); /* we do not need the KEK anymore */
    if (err != SECSuccess) {
        goto loser;
    }

    keyEncAlg_params = SEC_ASN1EncodeItem(poolp, NULL, &keyWrapAlg, SEC_ASN1_GET(SECOID_AlgorithmIDTemplate));
    if (keyEncAlg_params == NULL)
        goto loser;
    keyEncAlg_params->type = siBuffer;

    /* now set keyEncAlg */
    rv = SECOID_SetAlgorithmID(poolp, keyEncAlg, keyEncAlgtag, keyEncAlg_params);
    if (rv != SECSuccess) {
        goto loser;
    }

    return SECSuccess;

loser:
    if (publickey) {
        SECKEY_DestroyPublicKey(publickey);
    }
    if (ourPubKey) {
        SECKEY_DestroyPublicKey(ourPubKey);
    }
    if (ourPrivKey) {
        SECKEY_DestroyPrivateKey(ourPrivKey);
    }
    return SECFailure;
}

/* TODO: Move to pk11wrap and export? */
static int
cms_GetKekSizeFromKeyWrapAlgTag(SECOidTag keyWrapAlgtag)
{
    switch (keyWrapAlgtag) {
        case SEC_OID_AES_128_KEY_WRAP:
            return 16;
        case SEC_OID_AES_192_KEY_WRAP:
            return 24;
        case SEC_OID_AES_256_KEY_WRAP:
            return 32;
        default:
            break;
    }
    return 0;
}

/* TODO: Move to smimeutil and export? */
static CK_ULONG
cms_GetKdfFromKeyEncAlgTag(SECOidTag keyEncAlgtag)
{
    switch (keyEncAlgtag) {
        case SEC_OID_DHSINGLEPASS_STDDH_SHA1KDF_SCHEME:
        case SEC_OID_DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME:
            return CKD_SHA1_KDF;
        case SEC_OID_DHSINGLEPASS_STDDH_SHA224KDF_SCHEME:
        case SEC_OID_DHSINGLEPASS_COFACTORDH_SHA224KDF_SCHEME:
            return CKD_SHA224_KDF;
        case SEC_OID_DHSINGLEPASS_STDDH_SHA256KDF_SCHEME:
        case SEC_OID_DHSINGLEPASS_COFACTORDH_SHA256KDF_SCHEME:
            return CKD_SHA256_KDF;
        case SEC_OID_DHSINGLEPASS_STDDH_SHA384KDF_SCHEME:
        case SEC_OID_DHSINGLEPASS_COFACTORDH_SHA384KDF_SCHEME:
            return CKD_SHA384_KDF;
        case SEC_OID_DHSINGLEPASS_STDDH_SHA512KDF_SCHEME:
        case SEC_OID_DHSINGLEPASS_COFACTORDH_SHA512KDF_SCHEME:
            return CKD_SHA512_KDF;
        default:
            break;
    }
    return 0;
}

PK11SymKey *
NSS_CMSUtil_DecryptSymKey_ECDH(SECKEYPrivateKey *privkey, SECItem *encKey,
                               SECAlgorithmID *keyEncAlg, SECOidTag bulkalgtag,
                               SECItem *ukm, NSSCMSOriginatorIdentifierOrKey *oiok,
                               void *wincx)
{
    SECAlgorithmID keyWrapAlg;
    SECOidTag keyEncAlgtag, keyWrapAlgtag;
    CK_MECHANISM_TYPE target, keyDerivationType, keyWrapMech;
    CK_ULONG kdf;
    PK11SymKey *kek = NULL, *bulkkey = NULL;
    int kek_size;
    SECKEYPublicKey originatorpublickey;
    SECItem *oiok_publicKey, *SharedInfo = NULL;
    SECStatus rv;

    PORT_Memset(&keyWrapAlg, 0, sizeof(SECAlgorithmID));
    PORT_Memset(&originatorpublickey, 0, sizeof(SECKEYPublicKey));

    PORT_Assert(bulkalgtag != SEC_OID_UNKNOWN);
    target = PK11_AlgtagToMechanism(bulkalgtag);
    if (bulkalgtag == SEC_OID_UNKNOWN || target == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    keyEncAlgtag = SECOID_GetAlgorithmTag(keyEncAlg);
    keyDerivationType = PK11_AlgtagToMechanism(keyEncAlgtag);
    if ((keyEncAlgtag == SEC_OID_UNKNOWN) ||
        (keyDerivationType == CKM_INVALID_MECHANISM)) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    rv = SEC_ASN1DecodeItem(NULL, &keyWrapAlg,
                            SEC_ASN1_GET(SECOID_AlgorithmIDTemplate), &(keyEncAlg->parameters));
    if (rv != SECSuccess) {
        goto loser;
    }

    keyWrapAlgtag = SECOID_GetAlgorithmTag(&keyWrapAlg);
    keyWrapMech = PK11_AlgtagToMechanism(keyWrapAlgtag);
    if ((keyWrapAlgtag == SEC_OID_UNKNOWN) ||
        (keyWrapMech == CKM_INVALID_MECHANISM)) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    kek_size = cms_GetKekSizeFromKeyWrapAlgTag(keyWrapAlgtag);
    if (!kek_size) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    kdf = cms_GetKdfFromKeyEncAlgTag(keyEncAlgtag);
    if (!kdf) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    /* Get originator's public key */
    /* TODO: Add support for static-static ECDH */
    if (oiok->identifierType != NSSCMSOriginatorIDOrKey_OriginatorPublicKey) {
        PORT_SetError(SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE);
        goto loser;
    }

    /* PK11_PubDeriveWithKDF only uses the keyType u.ec.publicValue.data
     * and u.ec.publicValue.len from the originator's public key. */
    oiok_publicKey = &(oiok->id.originatorPublicKey.publicKey);
    originatorpublickey.keyType = ecKey;
    originatorpublickey.u.ec.publicValue.data = oiok_publicKey->data;
    originatorpublickey.u.ec.publicValue.len = oiok_publicKey->len / 8;

    SharedInfo = Create_ECC_CMS_SharedInfo(NULL, &keyWrapAlg, ukm, kek_size);
    if (!SharedInfo) {
        goto loser;
    }

    /* Generate the KEK (key exchange key) according to RFC5753 which we use
     * to wrap the bulk encryption key. */
    kek = PK11_PubDeriveWithKDF(privkey, &originatorpublickey, PR_TRUE,
                                NULL, NULL,
                                keyDerivationType, keyWrapMech,
                                CKA_WRAP, kek_size, kdf, SharedInfo, wincx);

    SECITEM_FreeItem(SharedInfo, PR_TRUE);

    if (kek == NULL) {
        goto loser;
    }

    bulkkey = PK11_UnwrapSymKey(kek, keyWrapMech, NULL, encKey, target, CKA_UNWRAP, 0);
    PK11_FreeSymKey(kek); /* we do not need the KEK anymore */
loser:
    SECOID_DestroyAlgorithmID(&keyWrapAlg, PR_FALSE);
    return bulkkey;
}

/* ====== ML-KEM (RFC 9629 / RFC 9936) ======================================= */

/*
 * RFC 9936 section 2.1's MUST-support pairing: the AES Key Wrap size is
 * keyed off the ML-KEM parameter set, and HKDF-SHA256 is the sole
 * mandatory KDF for all three parameter sets.
 */
static SECStatus
cms_GetMLKEMWrapParams(SECOidTag kemAlgTag, SECOidTag *wrapAlgTag,
                       unsigned int *kekSize)
{
    switch (kemAlgTag) {
        case SEC_OID_ML_KEM_512:
            *wrapAlgTag = SEC_OID_AES_128_KEY_WRAP;
            *kekSize = 16;
            break;
        case SEC_OID_ML_KEM_768:
        case SEC_OID_ML_KEM_1024:
            *wrapAlgTag = SEC_OID_AES_256_KEY_WRAP;
            *kekSize = 32;
            break;
        default:
            PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
            return SECFailure;
    }
    return SECSuccess;
}

/*
 * CMSORIforKEMOtherInfo ::= SEQUENCE {
 *     wrap KeyEncryptionAlgorithmIdentifier,
 *     kekLength INTEGER (1..65535),
 *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
 *
 * This is RFC 9629's HKDF "info" input. It is never a top-level encoded
 * object in its own right (unlike KEMRecipientInfo), so -- like
 * ECC_CMS_SharedInfo above -- it is kept local to this file rather than
 * added to cmsasn1.c/cmst.h.
 */
typedef struct CMSORIforKEMOtherInfoStr CMSORIforKEMOtherInfo;
struct CMSORIforKEMOtherInfoStr {
    SECAlgorithmID *wrap;
    SECItem kekLength;
    SECItem ukm; /* optional */
};

static const SEC_ASN1Template CMSORIforKEMOtherInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(CMSORIforKEMOtherInfo) },
    { SEC_ASN1_XTRN | SEC_ASN1_POINTER,
      offsetof(CMSORIforKEMOtherInfo, wrap),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_INTEGER,
      offsetof(CMSORIforKEMOtherInfo, kekLength) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED |
          SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_XTRN | 0,
      offsetof(CMSORIforKEMOtherInfo, ukm),
      SEC_ASN1_SUB(SEC_OctetStringTemplate) },
    { 0 }
};

/* kekSize is in octets (RFC 9629 section 3: "kekLength is the size of the
 * KEK in octets"). ukm may be NULL to omit it. */
static SECItem *
Create_CMS_KEM_OtherInfo(PLArenaPool *poolp, SECAlgorithmID *wrapAlgId,
                         unsigned int kekSize, SECItem *ukm)
{
    CMSORIforKEMOtherInfo otherInfo;

    PORT_Memset(&otherInfo, 0, sizeof(otherInfo));
    otherInfo.wrap = wrapAlgId;
    if (ukm) {
        otherInfo.ukm = *ukm;
    }

    if (SEC_ASN1EncodeInteger(poolp, &otherInfo.kekLength, (long)kekSize) == NULL) {
        return NULL;
    }

    return SEC_ASN1EncodeItem(poolp, NULL, &otherInfo, CMSORIforKEMOtherInfoTemplate);
}

/*
 * Derive the KEK from an ML-KEM shared secret via HKDF-SHA256, per
 * RFC 9629 section 5: IKM is the shared secret, info is the DER of
 * CMSORIforKEMOtherInfo, L (kekSize) is the requested output length, no
 * salt is used (all-zero default).
 */
static PK11SymKey *
cms_MLKEM_DeriveKEK(PK11SymKey *sharedSecret, SECItem *otherInfo,
                    CK_MECHANISM_TYPE wrapMech, unsigned int kekSize)
{
    CK_HKDF_PARAMS params;
    SECItem paramsItem;

    PORT_Memset(&params, 0, sizeof(params));
    params.bExtract = CK_TRUE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_NULL;
    params.pInfo = otherInfo->data;
    params.ulInfoLen = otherInfo->len;

    paramsItem.type = siBuffer;
    paramsItem.data = (unsigned char *)&params;
    paramsItem.len = sizeof(params);

    return PK11_Derive(sharedSecret, CKM_HKDF_DERIVE, &paramsItem, wrapMech,
                       CKA_WRAP, (int)kekSize);
}

SECStatus
NSS_CMSUtil_EncryptSymKey_MLKEM(PLArenaPool *poolp, CERTCertificate *cert,
                                PK11SymKey *bulkkey,
                                NSSCMSKEMRecipientInfo *kemRecipientInfo)
{
    SECOidTag kemAlgTag, wrapAlgTag;
    CK_MECHANISM_TYPE wrapMech;
    unsigned int kekSize, bulkkeySize;
    SECKEYPublicKey *publickey = NULL;
    PK11SymKey *sharedSecret = NULL;
    PK11SymKey *kek = NULL;
    SECItem *kemct = NULL;
    SECItem *otherInfo = NULL;
    SECStatus rv = SECFailure;

    kemAlgTag = SECOID_GetAlgorithmTag(&(cert->subjectPublicKeyInfo.algorithm));
    if (cms_GetMLKEMWrapParams(kemAlgTag, &wrapAlgTag, &kekSize) != SECSuccess) {
        return SECFailure;
    }
    wrapMech = PK11_AlgtagToMechanism(wrapAlgTag);
    if (wrapMech == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        return SECFailure;
    }

    bulkkeySize = PK11_GetKeyLength(bulkkey);
    if (bulkkeySize == 0) {
        return SECFailure;
    }

    publickey = CERT_ExtractPublicKey(cert);
    if (publickey == NULL) {
        goto loser;
    }

    if (PK11_Encapsulate(publickey, CKM_HKDF_DERIVE,
                         PK11_ATTR_SESSION | PK11_ATTR_PRIVATE |
                             PK11_ATTR_INSENSITIVE | PK11_ATTR_EXTRACTABLE,
                         CKF_DERIVE, &sharedSecret, &kemct) != SECSuccess) {
        goto loser;
    }

    if (SECOID_SetAlgorithmID(poolp, &kemRecipientInfo->kem, kemAlgTag, NULL) != SECSuccess) {
        goto loser;
    }
    if (SECOID_SetAlgorithmID(poolp, &kemRecipientInfo->kdf,
                              SEC_OID_HKDF_WITH_SHA256, NULL) != SECSuccess) {
        goto loser;
    }
    if (SECOID_SetAlgorithmID(poolp, &kemRecipientInfo->wrap, wrapAlgTag, NULL) != SECSuccess) {
        goto loser;
    }
    if (SEC_ASN1EncodeInteger(poolp, &kemRecipientInfo->kekLength, (long)kekSize) == NULL) {
        goto loser;
    }

    otherInfo = Create_CMS_KEM_OtherInfo(poolp, &kemRecipientInfo->wrap, kekSize, NULL);
    if (otherInfo == NULL) {
        goto loser;
    }

    kek = cms_MLKEM_DeriveKEK(sharedSecret, otherInfo, wrapMech, kekSize);
    if (kek == NULL) {
        goto loser;
    }

    if (SECITEM_CopyItem(poolp, &kemRecipientInfo->kemct, kemct) != SECSuccess) {
        goto loser;
    }

    /* AES key wrap output is 8 bytes longer than the input key (RFC 3394
     * section 2.2.1). */
    kemRecipientInfo->encryptedKey.len = bulkkeySize + 8;
    kemRecipientInfo->encryptedKey.data =
        (unsigned char *)PORT_ArenaAlloc(poolp, kemRecipientInfo->encryptedKey.len);
    if (kemRecipientInfo->encryptedKey.data == NULL) {
        goto loser;
    }

    if (PK11_WrapSymKey(wrapMech, NULL, kek, bulkkey, &kemRecipientInfo->encryptedKey) != SECSuccess) {
        goto loser;
    }

    rv = SECSuccess;

loser:
    if (publickey) {
        SECKEY_DestroyPublicKey(publickey);
    }
    if (sharedSecret) {
        PK11_FreeSymKey(sharedSecret);
    }
    if (kek) {
        PK11_FreeSymKey(kek);
    }
    if (kemct) {
        SECITEM_FreeItem(kemct, PR_TRUE);
    }
    return rv;
}

PK11SymKey *
NSS_CMSUtil_DecryptSymKey_MLKEM(SECKEYPrivateKey *privkey,
                                NSSCMSKEMRecipientInfo *kemRecipientInfo,
                                SECOidTag bulkalgtag)
{
    SECOidTag kemAlgTag, kdfAlgTag, wrapAlgTag;
    CK_MECHANISM_TYPE target, wrapMech;
    unsigned int kekSize;
    long kekLengthValue;
    PK11SymKey *sharedSecret = NULL;
    PK11SymKey *kek = NULL;
    PK11SymKey *bulkkey = NULL;
    SECItem *otherInfo = NULL;

    PORT_Assert(bulkalgtag != SEC_OID_UNKNOWN);
    target = PK11_AlgtagToMechanism(bulkalgtag);
    if (bulkalgtag == SEC_OID_UNKNOWN || target == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    kemAlgTag = SECOID_GetAlgorithmTag(&kemRecipientInfo->kem);
    if (kemAlgTag != SEC_OID_ML_KEM_512 && kemAlgTag != SEC_OID_ML_KEM_768 &&
        kemAlgTag != SEC_OID_ML_KEM_1024) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    kdfAlgTag = SECOID_GetAlgorithmTag(&kemRecipientInfo->kdf);
    if (kdfAlgTag != SEC_OID_HKDF_WITH_SHA256) {
        /* RFC 9936 only makes HKDF-SHA256 mandatory; this implementation
         * does not yet support any other KDF choice. */
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    wrapAlgTag = SECOID_GetAlgorithmTag(&kemRecipientInfo->wrap);
    wrapMech = PK11_AlgtagToMechanism(wrapAlgTag);
    if (wrapAlgTag == SEC_OID_UNKNOWN || wrapMech == CKM_INVALID_MECHANISM) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    if (SEC_ASN1DecodeInteger(&kemRecipientInfo->kekLength, (unsigned long *)&kekLengthValue) != SECSuccess) {
        goto loser;
    }
    kekSize = (unsigned int)kekLengthValue;

    if (PK11_Decapsulate(privkey, &kemRecipientInfo->kemct, CKM_HKDF_DERIVE,
                         PK11_ATTR_SESSION | PK11_ATTR_PRIVATE |
                             PK11_ATTR_INSENSITIVE | PK11_ATTR_EXTRACTABLE,
                         CKF_DERIVE, &sharedSecret) != SECSuccess) {
        goto loser;
    }

    otherInfo = Create_CMS_KEM_OtherInfo(NULL, &kemRecipientInfo->wrap, kekSize, NULL);
    if (otherInfo == NULL) {
        goto loser;
    }

    kek = cms_MLKEM_DeriveKEK(sharedSecret, otherInfo, wrapMech, kekSize);
    if (kek == NULL) {
        goto loser;
    }

    bulkkey = PK11_UnwrapSymKey(kek, wrapMech, NULL, &kemRecipientInfo->encryptedKey,
                                target, CKA_UNWRAP, 0);

loser:
    if (sharedSecret) {
        PK11_FreeSymKey(sharedSecret);
    }
    if (kek) {
        PK11_FreeSymKey(kek);
    }
    if (otherInfo) {
        SECITEM_FreeItem(otherInfo, PR_TRUE);
    }
    return bulkkey;
}
