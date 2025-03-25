#ifndef SECURITY_APP_H
#define SECURITY_APP_H

/*
** Required header files
*/
#include "cfe.h"
#include "security_app_platform_cfg.h"
#include "security_app_mission_cfg.h"
#include "security_app_msg.h"

/**
 * \defgroup cfsSECURITYAPP CFS Security Application
 * \{
 */

/*
** Security App macro definitions
*/
#define SECURITY_APP_SUCCESS           (0)
#define SECURITY_APP_ERROR             (-1)

#define SECURITY_APP_PIPE_DEPTH        32

/*
** Type definitions
*/
typedef struct
{
    /*
    ** Command interface counters
    */
    uint8   CmdCounter;
    uint8   ErrCounter;

    /*
    ** Housekeeping telemetry packet
    */
    SECURITY_APP_HkTlm_t   HkTlm;

    /*
    ** Operational data
    */
    CFE_SB_PipeId_t    CmdPipe;
    
    /*
    ** Run Status variable used in the main processing loop
    */
    uint32  RunStatus;

    /*
    ** Initialization data (not reported in housekeeping)
    */
    char    PipeName[16];
    uint16  PipeDepth;

} SECURITY_APP_Data_t;

/*
** Function prototypes
*/
void SECURITY_APP_Main(void);
int32 SECURITY_APP_Init(void);
void SECURITY_APP_ProcessCommandPacket(CFE_SB_MsgPtr_t Msg);
void SECURITY_APP_ReportHousekeeping(void);
bool SECURITY_APP_VerifyCmdLength(CFE_SB_MsgPtr_t Msg, uint16 ExpectedLength);
int32 SECURITY_APP_Noop(const SECURITY_APP_NoopCmd_t *Msg);
int32 SECURITY_APP_ResetCounters(const SECURITY_APP_ResetCountersCmd_t *Msg);
int32 SECURITY_APP_EncryptMsg(const SECURITY_APP_EncryptCmd_t *Msg);
int32 SECURITY_APP_DecryptMsg(const SECURITY_APP_DecryptCmd_t *Msg);

#endif /* SECURITY_APP_H */