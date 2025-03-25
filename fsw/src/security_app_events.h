#ifndef SECURITY_APP_EVENTS_H
#define SECURITY_APP_EVENTS_H

/*
** Event message IDs
*/
#define SECURITY_APP_RESERVED_EID              0  /* Reserved */
#define SECURITY_APP_STARTUP_INF_EID           1  /* Start up message "Security App initialized" */
#define SECURITY_APP_COMMAND_ERR_EID           2  /* Command Error */
#define SECURITY_APP_COMMANDNOP_INF_EID        3  /* "No-op" Command */
#define SECURITY_APP_COMMANDRST_INF_EID        4  /* "Reset Counters" Command */
#define SECURITY_APP_INVALID_MSGID_ERR_EID     5  /* Invalid Message ID */
#define SECURITY_APP_LEN_ERR_EID               6  /* Invalid command length */
#define SECURITY_APP_PIPE_ERR_EID              7  /* Command pipe creation error */

#define SECURITY_APP_ENCRYPT_INF_EID           8  /* Successful encryption */
#define SECURITY_APP_ENCRYPT_ERR_EID           9  /* Encryption error */
#define SECURITY_APP_DECRYPT_INF_EID           10 /* Successful decryption */
#define SECURITY_APP_DECRYPT_ERR_EID           11 /* Decryption error */
#define SECURITY_APP_INVALID_DATA_ERR_EID      12 /* Invalid data for encryption/decryption */

#endif /* SECURITY_APP_EVENTS_H */