/*
 * CheckPoint Zero Windows kernel checkpoint: file-system minifilter + process-creation callback.
 *
 * Design rule (same as the Linux BPF LSM): the kernel never parses content. It keeps three small tables
 * that checkpointd fills through a filter communication port and asks checkpointd when a decision needs
 * the detection engine:
 *
 *   AI lineage   pids of AI agents (by image name at creation, or registered by checkpointd for interpreted
 *                agents) and every process they create, inherited here in the create-process callback, so
 *                lineage cannot be lost between polls
 *   protected    NT path prefixes of credential files (\Device\HarddiskVolumeN\Users\a\.ssh, ...)
 *   enforce      1 enforce / 0 monitor
 *
 * Checkpoints
 *   process create (PsSetCreateProcessNotifyRoutineEx)  AI-lineage child: image + command line are sent to
 *       checkpointd, which judges them with the local engine and replies; Deny in enforce mode fails the
 *       creation with STATUS_ACCESS_DENIED before the process runs. No reply within CP_EXEC_TIMEOUT_MS ->
 *       allowed (fail open: an agent crash never blocks the user's tools).
 *   IRP_MJ_CREATE (minifilter pre-create)  AI-lineage open of a protected path -> STATUS_ACCESS_DENIED in
 *       enforce mode; reported either way. Keeps working if checkpointd is down.
 *
 * Build: Visual Studio 2022 + WDK (checkpoint.vcxproj). Load (test machine with test signing on):
 *   pnputil /add-driver checkpoint.inf /install  &&  fltmc load checkpoint
 */
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "checkpoint_shared.h"

#define CP_TAG        'zPCk'
#define CP_PID_SLOTS  8192                       /* power of two; open addressing */
#define CP_TOMBSTONE  0xFFFFFFFFu

typedef struct _CP_PID_SLOT {
    ULONG Pid;                                   /* 0 = empty, CP_TOMBSTONE = deleted */
    ULONG Root;
} CP_PID_SLOT;

static struct {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    volatile LONG Enforce;
    volatile LONG PidCount;
    EX_SPIN_LOCK PidLock;
    CP_PID_SLOT Pids[CP_PID_SLOTS];
    EX_PUSH_LOCK ProtectedLock;
    UNICODE_STRING Protected[CP_MAX_PROTECTED];
    ULONG ProtectedCount;
    UNICODE_STRING AiNames[CP_MAX_AI_NAMES];      /* guarded by ProtectedLock too */
    ULONG AiNameCount;
} G;

DRIVER_INITIALIZE DriverEntry;

/* ------------------------------------------------------------------ AI lineage table */

static ULONG CpSlot(ULONG Pid)
{
    return ((Pid >> 2) * 2654435761u) & (CP_PID_SLOTS - 1);     /* Windows pids are multiples of 4 */
}

static ULONG CpLineageRoot(ULONG Pid)
{
    ULONG root = 0, s, i;
    KIRQL irql;
    if (Pid == 0 || G.PidCount == 0)
        return 0;
    irql = ExAcquireSpinLockShared(&G.PidLock);
    for (i = 0, s = CpSlot(Pid); i < CP_PID_SLOTS; i++, s = (s + 1) & (CP_PID_SLOTS - 1)) {
        if (G.Pids[s].Pid == 0)
            break;
        if (G.Pids[s].Pid == Pid) {
            root = G.Pids[s].Root;
            break;
        }
    }
    ExReleaseSpinLockShared(&G.PidLock, irql);
    return root;
}

static VOID CpLineageAdd(ULONG Pid, ULONG Root)
{
    ULONG s, i, freeSlot = CP_PID_SLOTS;
    KIRQL irql;
    if (Pid == 0 || Pid == CP_TOMBSTONE)
        return;
    irql = ExAcquireSpinLockExclusive(&G.PidLock);
    for (i = 0, s = CpSlot(Pid); i < CP_PID_SLOTS; i++, s = (s + 1) & (CP_PID_SLOTS - 1)) {
        if (G.Pids[s].Pid == Pid) {
            G.Pids[s].Root = Root;
            freeSlot = CP_PID_SLOTS;
            goto done;
        }
        if (G.Pids[s].Pid == CP_TOMBSTONE && freeSlot == CP_PID_SLOTS)
            freeSlot = s;
        if (G.Pids[s].Pid == 0) {
            if (freeSlot == CP_PID_SLOTS)
                freeSlot = s;
            break;
        }
    }
    if (freeSlot != CP_PID_SLOTS) {               /* table full: the pid stays untracked (user-space poll still sees it) */
        G.Pids[freeSlot].Pid = Pid;
        G.Pids[freeSlot].Root = Root;
        InterlockedIncrement(&G.PidCount);
    }
done:
    ExReleaseSpinLockExclusive(&G.PidLock, irql);
}

static VOID CpLineageRemove(ULONG Pid)
{
    ULONG s, i;
    KIRQL irql;
    if (Pid == 0 || G.PidCount == 0)
        return;
    irql = ExAcquireSpinLockExclusive(&G.PidLock);
    for (i = 0, s = CpSlot(Pid); i < CP_PID_SLOTS; i++, s = (s + 1) & (CP_PID_SLOTS - 1)) {
        if (G.Pids[s].Pid == 0)
            break;
        if (G.Pids[s].Pid == Pid) {
            G.Pids[s].Pid = CP_TOMBSTONE;
            InterlockedDecrement(&G.PidCount);
            break;
        }
    }
    ExReleaseSpinLockExclusive(&G.PidLock, irql);
}

/* ------------------------------------------------------------------ protected paths */

static BOOLEAN CpIsProtected(PCUNICODE_STRING Name)
{
    BOOLEAN hit = FALSE;
    ULONG i;
    FltAcquirePushLockShared(&G.ProtectedLock);
    for (i = 0; i < G.ProtectedCount && !hit; i++)
        hit = RtlPrefixUnicodeString(&G.Protected[i], Name, TRUE);
    FltReleasePushLock(&G.ProtectedLock);
    return hit;
}

/* Adds a copy of Text to a string table guarded by ProtectedLock. */
static NTSTATUS CpAddString(UNICODE_STRING *Table, ULONG *Count, ULONG Max, PCWSTR Text)
{
    size_t cch = 0;
    PWCH copy;
    NTSTATUS status = STATUS_SUCCESS;
    if (!NT_SUCCESS(RtlStringCchLengthW(Text, CP_MAX_PATH, &cch)) || cch == 0)
        return STATUS_INVALID_PARAMETER;
    copy = ExAllocatePool2(POOL_FLAG_PAGED, cch * sizeof(WCHAR), CP_TAG);
    if (!copy)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy, Text, cch * sizeof(WCHAR));
    FltAcquirePushLockExclusive(&G.ProtectedLock);
    if (*Count < Max) {
        Table[*Count].Buffer = copy;
        Table[*Count].Length = Table[*Count].MaximumLength = (USHORT)(cch * sizeof(WCHAR));
        (*Count)++;
        copy = NULL;
    } else {
        status = STATUS_QUOTA_EXCEEDED;
    }
    FltReleasePushLock(&G.ProtectedLock);
    if (copy)
        ExFreePoolWithTag(copy, CP_TAG);
    return status;
}

static VOID CpClearStrings(UNICODE_STRING *Table, ULONG *Count)
{
    ULONG i;
    FltAcquirePushLockExclusive(&G.ProtectedLock);
    for (i = 0; i < *Count; i++) {
        ExFreePoolWithTag(Table[i].Buffer, CP_TAG);
        RtlZeroMemory(&Table[i], sizeof(UNICODE_STRING));
    }
    *Count = 0;
    FltReleasePushLock(&G.ProtectedLock);
}

/* \Device\...\Claude.exe -> is "claude" an AI agent name? */
static BOOLEAN CpIsAiImage(PCUNICODE_STRING Image)
{
    static const UNICODE_STRING exe = RTL_CONSTANT_STRING(L".exe");
    UNICODE_STRING stem, ext;
    USHORT i, len, start = 0;
    ULONG n;
    BOOLEAN hit = FALSE;
    if (Image == NULL || Image->Buffer == NULL || G.AiNameCount == 0)
        return FALSE;
    len = (USHORT)(Image->Length / sizeof(WCHAR));
    for (i = 0; i < len; i++)
        if (Image->Buffer[i] == L'\\')
            start = (USHORT)(i + 1);
    stem.Buffer = Image->Buffer + start;
    stem.Length = stem.MaximumLength = (USHORT)((len - start) * sizeof(WCHAR));
    if (stem.Length > exe.Length) {
        ext.Buffer = stem.Buffer + (stem.Length - exe.Length) / sizeof(WCHAR);
        ext.Length = ext.MaximumLength = exe.Length;
        if (RtlEqualUnicodeString(&ext, &exe, TRUE))
            stem.Length = stem.MaximumLength = (USHORT)(stem.Length - exe.Length);
    }
    FltAcquirePushLockShared(&G.ProtectedLock);
    for (n = 0; n < G.AiNameCount && !hit; n++)
        hit = RtlEqualUnicodeString(&G.AiNames[n], &stem, TRUE);
    FltReleasePushLock(&G.ProtectedLock);
    return hit;
}

/* ------------------------------------------------------------------ messages to checkpointd */

static VOID CpCopy(PWCH Dst, size_t Cch, PCUNICODE_STRING Src)
{
    Dst[0] = L'\0';
    if (Src && Src->Buffer && Src->Length)
        RtlStringCchCopyNW(Dst, Cch, Src->Buffer, Src->Length / sizeof(WCHAR));   /* truncates, always terminated */
}

/* Sends a notification; with Reply, waits up to TimeoutMs for checkpointd's answer. */
static NTSTATUS CpSend(PCP_NOTIFY Msg, PCP_REPLY Reply, ULONG TimeoutMs)
{
    LARGE_INTEGER timeout;
    ULONG replyLength = Reply ? (ULONG)sizeof(*Reply) : 0;
    if (G.ClientPort == NULL)
        return STATUS_PORT_DISCONNECTED;
    timeout.QuadPart = -10000LL * TimeoutMs;
    return FltSendMessage(G.Filter, &G.ClientPort, Msg, sizeof(*Msg), Reply, Reply ? &replyLength : NULL, &timeout);
}

/* ------------------------------------------------------------------ process-creation checkpoint */

static VOID CpProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG pid = HandleToULong(ProcessId), root;
    PCP_NOTIFY msg;
    CP_REPLY reply = { 0 };
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {                    /* exit */
        CpLineageRemove(pid);
        return;
    }
    root = CpLineageRoot(HandleToULong(CreateInfo->ParentProcessId));
    if (root == 0) {
        if (CpIsAiImage(CreateInfo->ImageFileName))
            CpLineageAdd(pid, pid);              /* an AI agent is starting: tracked before its first child */
        return;                                  /* not started by an AI agent: never delayed */
    }

    msg = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*msg), CP_TAG);
    if (msg) {
        msg->Kind = CpNotifyExec;
        msg->ProcessId = pid;
        msg->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        msg->RootProcessId = root;
        CpCopy(msg->ImagePath, CP_MAX_PATH, CreateInfo->ImageFileName);
        CpCopy(msg->CommandLine, CP_MAX_CMDLINE, CreateInfo->CommandLine);
        /* STATUS_TIMEOUT is a success code: only an actual answer can deny */
        if (CpSend(msg, &reply, CP_EXEC_TIMEOUT_MS) == STATUS_SUCCESS && reply.Deny && G.Enforce) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            ExFreePoolWithTag(msg, CP_TAG);
            return;
        }
        ExFreePoolWithTag(msg, CP_TAG);
    }
    CpLineageAdd(pid, root);
}

/* ------------------------------------------------------------------ file checkpoint */

static FLT_PREOP_CALLBACK_STATUS CpPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    BOOLEAN deny = FALSE;
    ULONG pid, root;
    PCP_NOTIFY msg;
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (G.ProtectedCount == 0 || G.PidCount == 0 || KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    pid = FltGetRequestorProcessId(Data);
    root = CpLineageRoot(pid);
    if (root == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (CpIsProtected(&name->Name)) {
        deny = (BOOLEAN)(G.Enforce != 0);
        msg = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*msg), CP_TAG);
        if (msg) {
            msg->Kind = CpNotifyFile;
            msg->ProcessId = pid;
            msg->RootProcessId = root;
            msg->Denied = deny;
            CpCopy(msg->ImagePath, CP_MAX_PATH, &name->Name);
            CpSend(msg, NULL, 20);
            ExFreePoolWithTag(msg, CP_TAG);
        }
    }
    FltReleaseFileNameInformation(name);
    if (deny) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------ communication port */

static NTSTATUS CpConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext,
                          PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    G.ClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID CpDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(G.Filter, &G.ClientPort);  /* tables and enforce mode stay: file protection survives an agent crash */
}

static NTSTATUS CpMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                          ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    CP_COMMAND cmd;
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(cmd))
        return STATUS_INVALID_PARAMETER;
    __try {
        RtlCopyMemory(&cmd, InputBuffer, sizeof(cmd));      /* user-mode buffer */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    cmd.Path[CP_MAX_PATH - 1] = L'\0';
    switch (cmd.Command) {
    case CpCmdSetEnforce:
        InterlockedExchange(&G.Enforce, cmd.Value ? 1 : 0);
        return STATUS_SUCCESS;
    case CpCmdAddAiRoot:
        CpLineageAdd(cmd.Value, cmd.Value);
        return STATUS_SUCCESS;
    case CpCmdAddProtected:
        return CpAddString(G.Protected, &G.ProtectedCount, CP_MAX_PROTECTED, cmd.Path);
    case CpCmdClearProtected:
        CpClearStrings(G.Protected, &G.ProtectedCount);
        return STATUS_SUCCESS;
    case CpCmdAddAiName:
        return CpAddString(G.AiNames, &G.AiNameCount, CP_MAX_AI_NAMES, cmd.Path);
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ------------------------------------------------------------------ registration */

static NTSTATUS CpUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PsSetCreateProcessNotifyRoutineEx(CpProcessNotify, TRUE);
    FltCloseCommunicationPort(G.ServerPort);
    FltUnregisterFilter(G.Filter);
    CpClearStrings(G.Protected, &G.ProtectedCount);
    CpClearStrings(G.AiNames, &G.AiNameCount);
    FltDeletePushLock(&G.ProtectedLock);
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, CpPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    CpUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&G, sizeof(G));
    FltInitializePushLock(&G.ProtectedLock);

    status = FltRegisterFilter(DriverObject, &Registration, &G.Filter);
    if (!NT_SUCCESS(status))
        return status;

    status = PsSetCreateProcessNotifyRoutineEx(CpProcessNotify, FALSE);   /* needs /INTEGRITYCHECK */
    if (!NT_SUCCESS(status))
        goto fail_filter;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);  /* SYSTEM and Administrators only */
    if (!NT_SUCCESS(status))
        goto fail_notify;
    RtlInitUnicodeString(&portName, CP_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
    status = FltCreateCommunicationPort(G.Filter, &G.ServerPort, &oa, NULL, CpConnect, CpDisconnect, CpMessage, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status))
        goto fail_notify;

    status = FltStartFiltering(G.Filter);
    if (NT_SUCCESS(status))
        return STATUS_SUCCESS;

    FltCloseCommunicationPort(G.ServerPort);
fail_notify:
    PsSetCreateProcessNotifyRoutineEx(CpProcessNotify, TRUE);
fail_filter:
    FltUnregisterFilter(G.Filter);
    return status;
}
