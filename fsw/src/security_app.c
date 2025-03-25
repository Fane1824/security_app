#include "security_app.h"
#include "security_app_crypto.h"
#include "security_app_events.h"
#include "security_app_version.h"

/*
** global data
*/
SECURITY_APP_Data_t SECURITY_APP_Data;

/* Application entry point and main process loop */
void SECURITY_APP_Main(void)
{
    int32 status;
    CFE_SB_MsgPtr_t Msg;

    /*
    ** Register the app with Executive services
    */
    CFE_ES_RegisterApp();

    /*
    ** Initialize the app
    */
    status = SECURITY_APP_Init();
    if (status != CFE_SUCCESS)
    {
        SECURITY_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /*
    ** Main process loop
    */
    while (CFE_ES_RunLoop(&SECURITY_APP_Data.RunStatus) == TRUE)
    {
        /*
        ** Wait for message arrival
        */
        status = CFE_SB_RcvMsg(&Msg, SECURITY_APP_Data.CmdPipe, CFE_SB_PEND_FOREVER);
        
        if (status == CFE_SUCCESS)
        {
            /*
            ** Process the received message
            */
            SECURITY_APP_ProcessCommandPacket(Msg);
        }
        else
        {
            /*
            ** Exit on error
            */
            CFE_EVS_SendEvent(SECURITY_APP_PIPE_ERR_EID, CFE_EVS_ERROR,
                             "SECURITY_APP: SB Pipe Read Error, App Will Exit");
            
            SECURITY_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Exit the application
    */
    CFE_ES_ExitApp(SECURITY_APP_Data.RunStatus);
}

/* Initialize application */
int32 SECURITY_APP_Init(void)
{
    int32 status;
    
    /*
    ** Initialize app command execution counters
    */
    SECURITY_APP_Data.CmdCounter = 0;
    SECURITY_APP_Data.ErrCounter = 0;
    
    /*
    ** Initialize app operational data
    */
    SECURITY_APP_Data.HkTlm.CommandCounter = 0;
    SECURITY_APP_Data.HkTlm.CommandErrorCounter = 0;
    SECURITY_APP_Data.HkTlm.EncryptionCount = 0;
    SECURITY_APP_Data.HkTlm.DecryptionCount = 0;
    SECURITY_APP_Data.HkTlm.EncryptionErrorCount = 0;
    SECURITY_APP_Data.HkTlm.DecryptionErrorCount = 0;
    
    /*
    ** Initialize crypto subsystem
    */
    if (SECURITY_APP_InitCrypto() != 0)
    {
        CFE_EVS_SendEvent(SECURITY_APP_STARTUP_INF_EID, CFE_EVS_ERROR,
                         "SECURITY_APP: Failed to initialize crypto subsystem");
        return CFE_ES_RunStatus_APP_ERROR;
    }
    
    /*
    ** Initialize app configuration data
    */
    strncpy(SECURITY_APP_Data.PipeName, "SECURITY_APP_CMD_PIPE", sizeof(SECURITY_APP_Data.PipeName));
    SECURITY_APP_Data.PipeDepth = SECURITY_APP_PIPE_DEPTH;

    /*
    ** Register for event services
    */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("Security App: Error Registering For Event Services, RC = 0x%08X\n", (unsigned int)status);
        return status;
    }

    /*
    ** Initialize housekeeping packet (clear user data area)
    */
    CFE_SB_InitMsg(&SECURITY_APP_Data.HkTlm, SECURITY_APP_HK_TLM_MID, sizeof(SECURITY_APP_HkTlm_t), TRUE);

    /*
    ** Create Software Bus message pipe
    */
    status = CFE_SB_CreatePipe(&SECURITY_APP_Data.CmdPipe, SECURITY_APP_Data.PipeDepth, SECURITY_APP_Data.PipeName);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SECURITY_APP_PIPE_ERR_EID, CFE_EVS_ERROR,
                         "Error creating command pipe, RC = 0x%08X", (unsigned int)status);
        return status;
    }
    
    /*
    ** Subscribe to Housekeeping request commands
    */
    status = CFE_SB_Subscribe(SECURITY_APP_SEND_HK_MID, SECURITY_APP_Data.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SECURITY_APP_PIPE_ERR_EID, CFE_EVS_ERROR,
                         "Error subscribing to HK request, RC = 0x%08X", (unsigned int)status);
        return status;
    }

    /*
    ** Subscribe to Security App command packets
    */
    status = CFE_SB_Subscribe(SECURITY_APP_CMD_MID, SECURITY_APP_Data.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SECURITY_APP_PIPE_ERR_EID, CFE_EVS_ERROR,
                         "Error subscribing to command packets, RC = 0x%08X", (unsigned int)status);
        return status;
    }

    /*
    ** Application startup event message
    */
    CFE_EVS_SendEvent(SECURITY_APP_STARTUP_INF_EID, CFE_EVS_INFORMATION,
                     "SECURITY_APP Initialized. Version %d.%d.%d.%d",
                     SECURITY_APP_MAJOR_VERSION, SECURITY_APP_MINOR_VERSION,
                     SECURITY_APP_REVISION, SECURITY_APP_MISSION_REV);
                     
    /*
    ** Set run status to indicate app is running
    */
    SECURITY_APP_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;

    return CFE_SUCCESS;
}

/* Process a command packet */
void SECURITY_APP_ProcessCommandPacket(CFE_SB_MsgPtr_t Msg)
{
    CFE_SB_MsgId_t MsgId;

    MsgId = CFE_SB_GetMsgId(Msg);

    switch (MsgId)
    {
        /*
        ** Housekeeping telemetry request
        */
        case SECURITY_APP_SEND_HK_MID:
            SECURITY_APP_ReportHousekeeping();
            break;

        /*
        ** Security App commands
        */
        case SECURITY_APP_CMD_MID:
        {
            uint16 CommandCode = CFE_SB_GetCmdCode(Msg);

            switch (CommandCode)
            {
                /*
                ** No-Op command
                */
                case SECURITY_APP_NOOP_CC:
                    if (SECURITY_APP_VerifyCmdLength(Msg, sizeof(SECURITY_APP_NoopCmd_t)))
                    {
                        SECURITY_APP_Noop((SECURITY_APP_NoopCmd_t *)Msg);
                    }
                    break;

                /*
                ** Reset counters command
                */
                case SECURITY_APP_RESET_COUNTERS_CC:
                    if (SECURITY_APP_VerifyCmdLength(Msg, sizeof(SECURITY_APP_ResetCountersCmd_t)))
                    {
                        SECURITY_APP_ResetCounters((SECURITY_APP_ResetCountersCmd_t *)Msg);
                    }
                    break;
                    
                /*
                ** Encrypt message command
                */
                case SECURITY_APP_ENCRYPT_CC:
                    if (SECURITY_APP_VerifyCmdLength(Msg, sizeof(SECURITY_APP_EncryptCmd_t)))
                    {
                        SECURITY_APP_EncryptMsg((SECURITY_APP_EncryptCmd_t *)Msg);
                    }
                    break;
                    
                /*
                ** Decrypt message command
                */
                case SECURITY_APP_DECRYPT_CC:
                    if (SECURITY_APP_VerifyCmdLength(Msg, sizeof(SECURITY_APP_DecryptCmd_t)))
                    {
                        SECURITY_APP_DecryptMsg((SECURITY_APP_DecryptCmd_t *)Msg);
                    }
                    break;

                /*
                ** Invalid command code
                */
                default:
                    SECURITY_APP_Data.ErrCounter++;
                    CFE_EVS_SendEvent(SECURITY_APP_COMMAND_ERR_EID, CFE_EVS_ERROR,
                                     "Invalid command code: CC = %d", CommandCode);
                    break;
            }
            break;
        }

        /*
        ** Invalid message ID
        */
        default:
            SECURITY_APP_Data.ErrCounter++;
            CFE_EVS_SendEvent(SECURITY_APP_INVALID_MSGID_ERR_EID, CFE_EVS_ERROR,
                             "Invalid message ID: 0x%04X", MsgId);
            break;
    }
}

/* Report housekeeping telemetry */
void SECURITY_APP_ReportHousekeeping(void)
{
    /*
    ** Update housekeeping values
    */
    SECURITY_APP_Data.HkTlm.CommandCounter = SECURITY_APP_Data.CmdCounter;
    SECURITY_APP_Data.HkTlm.CommandErrorCounter = SECURITY_APP_Data.ErrCounter;
    
    /*
    ** Send housekeeping telemetry packet
    */
    CFE_SB_TimeStampMsg((CFE_SB_MsgPtr_t)&SECURITY_APP_Data.HkTlm);
    CFE_SB_SendMsg((CFE_SB_MsgPtr_t)&SECURITY_APP_Data.HkTlm);
}

/* Verify command packet length */
bool SECURITY_APP_VerifyCmdLength(CFE_SB_MsgPtr_t Msg, uint16 ExpectedLength)
{
    bool result = TRUE;
    uint16 ActualLength = CFE_SB_GetTotalMsgLength(Msg);

    /*
    ** Verify the command packet length
    */
    if (ExpectedLength != ActualLength)
    {
        SECURITY_APP_Data.ErrCounter++;
        CFE_EVS_SendEvent(SECURITY_APP_LEN_ERR_EID, CFE_EVS_ERROR,
                         "Invalid msg length: expected = %d, actual = %d",
                         ExpectedLength, ActualLength);
        result = FALSE;
    }

    return result;
}

/* NOOP command handler */
int32 SECURITY_APP_Noop(const SECURITY_APP_NoopCmd_t *Msg)
{
    SECURITY_APP_Data.CmdCounter++;

    CFE_EVS_SendEvent(SECURITY_APP_COMMANDNOP_INF_EID, CFE_EVS_INFORMATION,
                     "SECURITY_APP: NOOP command received");
    return CFE_SUCCESS;
}

/* Reset counters command handler */
int32 SECURITY_APP_ResetCounters(const SECURITY_APP_ResetCountersCmd_t *Msg)
{
    SECURITY_APP_Data.CmdCounter = 0;
    SECURITY_APP_Data.ErrCounter = 0;

    SECURITY_APP_Data.HkTlm.EncryptionCount = 0;
    SECURITY_APP_Data.HkTlm.DecryptionCount = 0;
    SECURITY_APP_Data.HkTlm.EncryptionErrorCount = 0;
    SECURITY_APP_Data.HkTlm.DecryptionErrorCount = 0;

    CFE_EVS_SendEvent(SECURITY_APP_COMMANDRST_INF_EID, CFE_EVS_INFORMATION,
                     "SECURITY_APP: RESET counters command received");
    return CFE_SUCCESS;
}

/* Encrypt message command handler */
int32 SECURITY_APP_EncryptMsg(const SECURITY_APP_EncryptCmd_t *Msg)
{
    int32_t status;
    SECURITY_APP_EncryptedTlm_t EncryptedTlm;
    size_t encrypted_len;
    
    SECURITY_APP_Data.CmdCounter++;
    
    /* Validate input */
    if (Msg->DataLength == 0 || Msg->DataLength > SECURITY_APP_MAX_DATA_LENGTH)
    {
        SECURITY_APP_Data.HkTlm.EncryptionErrorCount++;
        CFE_EVS_SendEvent(SECURITY_APP_INVALID_DATA_ERR_EID, CFE_EVS_ERROR,
                         "SECURITY_APP: Invalid data length for encryption: %d", Msg->DataLength);
        return CFE_SUCCESS;
    }
    
    /* Initialize telemetry packet */
    CFE_SB_InitMsg(&EncryptedTlm, Msg->TargetMsgID, sizeof(SECURITY_APP_EncryptedTlm_t), TRUE);
    
    /* Store original data length */
    EncryptedTlm.OriginalDataLength = Msg->DataLength;
    
    /* Encrypt the data */
    status = SECURITY_APP_Encrypt(Msg->Data, Msg->DataLength,
                                 EncryptedTlm.IV, EncryptedTlm.EncryptedData, &encrypted_len);
    
    if (status != 0)
    {
        SECURITY_APP_Data.HkTlm.EncryptionErrorCount++;
        CFE_EVS_SendEvent(SECURITY_APP_ENCRYPT_ERR_EID, CFE_EVS_ERROR,
                         "SECURITY_APP: Encryption failed with error: %d", status);
        return CFE_SUCCESS;
    }
    
    /* Update telemetry */
    EncryptedTlm.EncryptedDataLength = encrypted_len;
    
    /* Send encrypted data */
    CFE_SB_TimeStampMsg((CFE_SB_MsgPtr_t)&EncryptedTlm);
    CFE_SB_SendMsg((CFE_SB_MsgPtr_t)&EncryptedTlm);
    
    /* Update housekeeping */
    SECURITY_APP_Data.HkTlm.EncryptionCount++;
    
    /* Log success */
    CFE_EVS_SendEvent(SECURITY_APP_ENCRYPT_INF_EID, CFE_EVS_INFORMATION,
                     "SECURITY_APP: Encrypted %d bytes of data", Msg->DataLength);
    
    return CFE_SUCCESS;
}

/* Decrypt message command handler */
int32 SECURITY_APP_DecryptMsg(const SECURITY_APP_DecryptCmd_t *Msg)
{
    int32_t status;
    SECURITY_APP_DecryptedTlm_t DecryptedTlm;
    size_t decrypted_len;
    
    SECURITY_APP_Data.CmdCounter++;
    
    /* Validate input */
    if (Msg->DataLength == 0 || Msg->DataLength > SECURITY_APP_MAX_DATA_LENGTH)
    {
        SECURITY_APP_Data.HkTlm.DecryptionErrorCount++;
        CFE_EVS_SendEvent(SECURITY_APP_INVALID_DATA_ERR_EID, CFE_EVS_ERROR,
                         "SECURITY_APP: Invalid data length for decryption: %d", Msg->DataLength);
        return CFE_SUCCESS;
    }
    
    /* Initialize telemetry packet */
    CFE_SB_InitMsg(&DecryptedTlm, Msg->TargetMsgID, sizeof(SECURITY_APP_DecryptedTlm_t), TRUE);
    
    /* Extract encrypted data and IV from command */
    uint8_t *iv = (uint8_t *)(Msg->Data);
    uint32_t original_len = *(uint32_t *)(iv + 16);
    uint8_t *encrypted_data = iv + 16 + sizeof(uint32_t);
    uint16_t encrypted_len = Msg->DataLength - 16 - sizeof(uint32_t);
    
    /* Decrypt the data */
    status = SECURITY_APP_Decrypt(encrypted_data, encrypted_len,
                                 iv, DecryptedTlm.Data, &decrypted_len, original_len);
    
    if (status != 0)
    {
        SECURITY_APP_Data.HkTlm.DecryptionErrorCount++;
        CFE_EVS_SendEvent(SECURITY_APP_DECRYPT_ERR_EID, CFE_EVS_ERROR,
                         "SECURITY_APP: Decryption failed with error: %d", status);
        return CFE_SUCCESS;
    }
    
    /* Update telemetry */
    DecryptedTlm.DataLength = decrypted_len;
    
    /* Send decrypted data */
    CFE_SB_TimeStampMsg((CFE_SB_MsgPtr_t)&DecryptedTlm);
    CFE_SB_SendMsg((CFE_SB_MsgPtr_t)&DecryptedTlm);
    
    /* Update housekeeping */
    SECURITY_APP_Data.HkTlm.DecryptionCount++;
    
    /* Log success */
    CFE_EVS_SendEvent(SECURITY_APP_DECRYPT_INF_EID, CFE_EVS_INFORMATION,
                     "SECURITY_APP: Decrypted %d bytes of data", decrypted_len);
    
    return CFE_SUCCESS;
}