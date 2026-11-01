/*
 * Messages between the CheckPoint Zero minifilter (checkpoint.sys) and checkpointd.
 * The Python side (agent/checkpointd/sensors/windows_driver.py) packs the same layouts with ctypes;
 * change both together.
 */
#pragma once

#define CP_PORT_NAME        L"\\CheckPointZeroPort"
#define CP_MAX_PATH         260
#define CP_MAX_CMDLINE      1024
#define CP_MAX_PROTECTED    128
#define CP_MAX_AI_NAMES     64
#define CP_EXEC_TIMEOUT_MS  250          /* no answer from checkpointd in time -> allow (fail open) */

/* driver -> checkpointd */
typedef enum _CP_NOTIFY_KIND {
    CpNotifyExec = 1,                    /* AI-lineage process is being created; reply decides */
    CpNotifyFile = 2                     /* AI-lineage open of a protected credential path (informational) */
} CP_NOTIFY_KIND;

typedef struct _CP_NOTIFY {
    ULONG Kind;
    ULONG ProcessId;                     /* new process (exec) or requesting process (file) */
    ULONG ParentProcessId;
    ULONG RootProcessId;                 /* the AI agent this lineage started from */
    ULONG Denied;                        /* file: 1 if the open was failed with STATUS_ACCESS_DENIED */
    ULONG Reserved;
    WCHAR ImagePath[CP_MAX_PATH];        /* exec: image; file: NT path of the file */
    WCHAR CommandLine[CP_MAX_CMDLINE];   /* exec only */
} CP_NOTIFY, *PCP_NOTIFY;

typedef struct _CP_REPLY {
    ULONG Deny;                          /* 1 -> process creation fails with STATUS_ACCESS_DENIED (enforce mode) */
} CP_REPLY, *PCP_REPLY;

/* checkpointd -> driver */
typedef enum _CP_COMMAND_KIND {
    CpCmdSetEnforce = 1,                 /* Value: 1 enforce, 0 monitor */
    CpCmdAddAiRoot = 2,                  /* Value: pid of an AI agent; its descendants inherit it in-kernel */
    CpCmdAddProtected = 3,               /* Path: NT path prefix, e.g. \Device\HarddiskVolume3\Users\a\.ssh */
    CpCmdClearProtected = 4,
    CpCmdAddAiName = 5                   /* Path: image name without .exe (claude, cursor, ...): becomes an AI root at create */
} CP_COMMAND_KIND;

typedef struct _CP_COMMAND {
    ULONG Command;
    ULONG Value;
    WCHAR Path[CP_MAX_PATH];
} CP_COMMAND, *PCP_COMMAND;
