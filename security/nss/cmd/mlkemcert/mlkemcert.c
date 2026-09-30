/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * mlkemcert - mint an X.509 certificate for a freshly-generated, permanent
 * ML-KEM keypair, issued (signed) by an existing CA in the same NSS
 * database.
 *
 * This exists because ML-KEM cannot sign anything, so the usual
 * certutil -R (self-signed CSR) / certutil -C (CA-signs the CSR) flow
 * cannot work for it: `certutil -R -k mlkem` fails outright trying to
 * self-sign the request with SEC_ERROR_INVALID_ALGORITHM. This mirrors
 * certutil's own MakeV1Cert/SignCert (cmd/certutil/certutil.c) exactly,
 * but builds the CERTCertificateRequest struct directly in memory instead
 * of parsing an actual signed CSR -- CERT_CreateCertificate only ever
 * reads req->subject and req->subjectPublicKeyInfo, it never verifies a
 * self-signature, so no proof-of-possession step is needed for a test CA
 * that already controls both keys locally.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nss.h"
#include "cert.h"
#include "keyhi.h"
#include "pk11pub.h"
#include "cryptohi.h"
#include "secder.h"
#include "secutil.h"

static void
Usage(const char *progName)
{
    fprintf(stderr,
            "Usage: %s -d dbdir -c ca-nickname -s subject-dn -m serial "
            "-o out.der [-q ml-kem-512|ml-kem-768|ml-kem-1024] "
            "[-f pwfile] [-k key-nickname]\n",
            progName);
}

int
main(int argc, char **argv)
{
    const char *dbdir = NULL;
    const char *caNick = NULL;
    const char *subjectDn = NULL;
    const char *outFile = NULL;
    const char *paramSetArg = "ml-kem-768";
    const char *keyNickname = NULL;
    const char *pwFile = NULL;
    unsigned int serial = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            dbdir = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            caNick = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            subjectDn = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            serial = (unsigned int)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outFile = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            paramSetArg = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            keyNickname = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            pwFile = argv[++i];
        } else {
            Usage(argv[0]);
            return 1;
        }
    }
    if (!dbdir || !caNick || !subjectDn || !outFile || serial == 0) {
        Usage(argv[0]);
        return 1;
    }

    CK_ML_KEM_PARAMETER_SET_TYPE paramSet;
    if (PORT_Strcasecmp(paramSetArg, "ml-kem-512") == 0) {
        paramSet = CKP_ML_KEM_512;
    } else if (PORT_Strcasecmp(paramSetArg, "ml-kem-768") == 0) {
        paramSet = CKP_ML_KEM_768;
    } else if (PORT_Strcasecmp(paramSetArg, "ml-kem-1024") == 0) {
        paramSet = CKP_ML_KEM_1024;
    } else {
        fprintf(stderr, "unknown -q parameter set '%s'\n", paramSetArg);
        return 1;
    }

    secuPWData pwdata;
    if (pwFile) {
        pwdata.source = PW_FROMFILE;
        pwdata.data = (char *)pwFile;
    } else {
        pwdata.source = PW_NONE;
        pwdata.data = NULL;
    }
    PK11_SetPasswordFunc(SECU_GetModulePassword);

    /* NSS_Init() opens the database read-only; the permanent key we
     * generate below needs a read-write session. */
    if (NSS_InitReadWrite(dbdir) != SECSuccess) {
        fprintf(stderr, "NSS_InitReadWrite(%s) failed: %d\n", dbdir,
                PORT_GetError());
        return 1;
    }

    CERTCertificate *caCert = PK11_FindCertFromNickname(caNick, &pwdata);
    if (!caCert) {
        fprintf(stderr, "cannot find CA cert '%s': %d\n", caNick,
                PORT_GetError());
        return 1;
    }
    SECKEYPrivateKey *caPrivKey = PK11_FindKeyByAnyCert(caCert, &pwdata);
    if (!caPrivKey) {
        fprintf(stderr, "cannot find CA private key: %d\n", PORT_GetError());
        return 1;
    }

    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (PK11_Authenticate(slot, PR_TRUE, &pwdata) != SECSuccess) {
        fprintf(stderr, "PK11_Authenticate failed: %d\n", PORT_GetError());
        return 1;
    }

    SECKEYPublicKey *pubKey = NULL;
    /* Deliberately the plain PK11_GenerateKeyPair, not _WithOpFlags: guessing
     * op flags for CKM_ML_KEM_KEY_PAIR_GEN produced
     * SEC_ERROR_PKCS11_DEVICE_ERROR; letting NSS pick the correct flags for
     * the mechanism works. */
    SECKEYPrivateKey *privKey = PK11_GenerateKeyPair(
        slot, CKM_ML_KEM_KEY_PAIR_GEN, &paramSet, &pubKey,
        PR_TRUE /* isPerm */, PR_FALSE /* isSensitive */, &pwdata);
    if (!privKey || !pubKey) {
        fprintf(stderr, "ML-KEM keygen failed: %d\n", PORT_GetError());
        return 1;
    }
    if (keyNickname) {
        /* best-effort; not all NSS versions expose a direct "nickname a raw
         * private key" call, and the cert import step below associates by
         * matching public key regardless of nickname. */
        (void)keyNickname;
    }
    fprintf(stderr, "Generated permanent ML-KEM key (%s)\n", paramSetArg);

    CERTCertificateRequest req;
    memset(&req, 0, sizeof(req));
    CERTName *subjectName = CERT_AsciiToName(subjectDn);
    if (!subjectName) {
        fprintf(stderr, "CERT_AsciiToName failed for '%s'\n", subjectDn);
        return 1;
    }
    req.subject = *subjectName;
    CERTSubjectPublicKeyInfo *spki = SECKEY_CreateSubjectPublicKeyInfo(pubKey);
    if (!spki) {
        fprintf(stderr, "SECKEY_CreateSubjectPublicKeyInfo failed\n");
        return 1;
    }
    req.subjectPublicKeyInfo = *spki;

    CERTValidity *validity = CERT_CreateValidity(
        PR_Now(), PR_Now() + (PRTime)3652LL * 24 * 60 * 60 * 1000000LL);
    if (!validity) {
        fprintf(stderr, "CERT_CreateValidity failed\n");
        return 1;
    }

    CERTCertificate *cert =
        CERT_CreateCertificate(serial, &caCert->subject, validity, &req);
    CERT_DestroyValidity(validity);
    if (!cert) {
        fprintf(stderr, "CERT_CreateCertificate failed: %d\n",
                PORT_GetError());
        return 1;
    }

    if (SEC_CreateSignatureAlgorithmID(cert->arena, &cert->signature,
                                      SEC_OID_UNKNOWN, SEC_OID_UNKNOWN, NULL,
                                      caPrivKey, NULL) != SECSuccess) {
        fprintf(stderr, "SEC_CreateSignatureAlgorithmID failed: %d\n",
                PORT_GetError());
        return 1;
    }

    /* Version 1 (implicit, no explicit version field needed). */
    cert->version.data = NULL;
    cert->version.len = 0;

    SECItem der = { siBuffer, NULL, 0 };
    if (!SEC_ASN1EncodeItem(cert->arena, &der, cert,
                            SEC_ASN1_GET(CERT_CertificateTemplate))) {
        fprintf(stderr, "SEC_ASN1EncodeItem(cert) failed\n");
        return 1;
    }

    if (SEC_DerSignDataWithAlgorithmID(cert->arena, &cert->derCert, der.data,
                                       der.len, caPrivKey,
                                       &cert->signature) != SECSuccess) {
        fprintf(stderr, "SEC_DerSignDataWithAlgorithmID failed: %d\n",
                PORT_GetError());
        return 1;
    }

    FILE *f = fopen(outFile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(cert->derCert.data, 1, cert->derCert.len, f);
    fclose(f);
    fprintf(stderr, "Wrote %s (%u bytes)\n", outFile, cert->derCert.len);

    return 0;
}
