#ifndef SECURITY_APP_MSG_H
#define SECURITY_APP_MSG_H

#include "cfe.h"

/*
** Security App command codes
*/
#define SECURITY_APP_NOOP_CC              0
#define SECURITY_APP_RESET_COUNTERS_CC    1
#define SECURITY_APP_ENCRYPT_CC           2
#define SECURITY_APP_DECRYPT_CC           3

/*
** Type definition (generic "no arguments" command)
*/
typedef struct
{
    uint8   CmdHeader[CFE_SB_CMD_HDR_SIZE];

} SECURITY_APP_NoArgsCmd_t;

/*
** The following commands all share the "NoArgs" format
**
** They are each given their own type name matching the command name, which
** allows them to change independently in the future without changing the prototype
** of the handler function
*/
typedef SECURITY_APP_NoArgsCmd_t SECURITY_APP_NoopCmd_t;
typedef SECURITY_APP_NoArgsCmd_t SECURITY_APP_ResetCountersCmd_t;

/*
** Type definition (Encryption command)
*/
#define SECURITY_APP_MAX_DATA_LENGTH 1024

typedef struct
{
    uint8   CmdHeader[CFE_SB_CMD_HDR_SIZE];
    uint16  DataLength;                             /* Length of data to be encrypted */
    uint8   Data[SECURITY_APP_MAX_DATA_LENGTH];     /* Data to be encrypted */
    uint16  TargetMsgID;                            /* Message ID to use for encrypted output */

} SECURITY_APP_EncryptCmd_t;

/*
** Type definition (Decryption command)
*/
typedef struct
{
    uint8   CmdHeader[CFE_SB_CMD_HDR_SIZE];
    uint16  DataLength;                             /* Length of data to be decrypted */
    uint8   Data[SECURITY_APP_MAX_DATA_LENGTH];     /* Data to be decrypted */
    uint16  TargetMsgID;                            /* Message ID to use for decrypted output */

} SECURITY_APP_DecryptCmd_t;

/*
** Type definition (Encrypted data telemetry)
*/
typedef struct
{
    uint8    TlmHeader[CFE_SB_TLM_HDR_SIZE];
    uint32   OriginalDataLength;                     /* Original data length before encryption */
    uint16   EncryptedDataLength;                    /* Length of encrypted data */
    uint8    IV[16];                                 /* Initialization Vector */
    uint8    EncryptedData[SECURITY_APP_MAX_DATA_LENGTH]; /* Encrypted data */

} SECURITY_APP_EncryptedTlm_t;

/*
** Type definition (Decrypted data telemetry)
*/
typedef struct
{
    uint8    TlmHeader[CFE_SB_TLM_HDR_SIZE];
    uint16   DataLength;                             /* Length of decrypted data */
    uint8    Data[SECURITY_APP_MAX_DATA_LENGTH];     /* Decrypted data */

} SECURITY_APP_DecryptedTlm_t;

/*
** Type definition (housekeeping)
*/
typedef struct
{
    uint8    TlmHeader[CFE_SB_TLM_HDR_SIZE];
    uint8    CommandCounter;
    uint8    CommandErrorCounter;
    uint8    spare[2];
    uint32   EncryptionCount;
    uint32   DecryptionCount;
    uint32   EncryptionErrorCount;
    uint32   DecryptionErrorCount;

} SECURITY_APP_HkTlm_t;

#endif /* SECURITY_APP_MSG_H */