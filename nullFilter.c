#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

//https://github.com/microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/nullFilter

PFLT_FILTER FilterHandle = NULL;
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPostRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

const FLT_OPERATION_REGISTRATION Callbacks[] = {
 {IRP_MJ_CREATE, 0, MiniPreCreate, MiniPostCreate},
 {IRP_MJ_WRITE, 0, MiniPreWrite, NULL},
 {IRP_MJ_READ, 0, NULL, MiniPostRead},
 {IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION FilterRegistration = {
 sizeof(FLT_REGISTRATION),
 FLT_REGISTRATION_VERSION,
 0,
 NULL,
 Callbacks,
 MiniUnload,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL
};

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    KdPrint(("Driver unloaded2 \r\n"));
    FltUnregisterFilter(FilterHandle);

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    //KdPrint(("Post create is running \r\n"));
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {

            if (FileNameInfo->Name.MaximumLength < 200)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                //KdPrint(("Create file: %ws \r\n", Name));
            }
        }

        FltReleaseFileNameInformation(FileNameInfo);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };
    

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {

            if (FileNameInfo->Name.MaximumLength < 200)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                _wcsupr(Name);
                if (wcsstr(Name, L"OPENME.TXT") != NULL)
                {
                    char* ioBuffer = NULL;
                    PMDL MdlAddress = Data->Iopb->Parameters.Write.MdlAddress;
                    ULONG Length = (ULONG)Data->Iopb->Parameters.Write.Length;
                    if (NULL != MdlAddress)
                    {
                        // Don't expect chained MDLs this high up the stack
                        ASSERT(MdlAddress->Next == NULL);
                        ioBuffer = (char*)MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority);
                    }
                    else
                    {
                        ioBuffer = (char*)Data->Iopb->Parameters.Write.WriteBuffer;
                    }
                    KdPrint(("Write file: %ws blocked \r\n", Name));

                    if (ioBuffer != NULL)
                    {
                        KdPrint(("the write buffer is: %s", ioBuffer));
                    }
                    else {
                        KdPrint(("the write buffer is null"));
                    }


                    Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    Data->IoStatus.Information = 0;
                    FltReleaseFileNameInformation(FileNameInfo);


                    return FLT_PREOP_COMPLETE; //this return status will make the Io manager to not move the irp to the lower drivers
                }
                //KdPrint(("Write file: %ws \r\n", Name));
                FltReleaseFileNameInformation(FileNameInfo);

                
                //WCHAR str = { 0 };
                
                //wcsncpy(str, (WCHAR)Buffer, 10);
                

                /*status=FltAllocateContext(FilterHandle, FLT_FILE_CONTEXT, MAXUSHORT, NonPagedPool, &context);
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed alloc context \r\n"));
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }

                RtlZeroMemory(context, MAXUSHORT);
                

                
                
                if (!NT_SUCCESS(status))
                {
                    KdPrint(("failed get file context \r\n"));
                    FltReleaseContext(context);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }*/


                
            }
        }

        
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS MiniPostRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status;
    WCHAR Name[200] = { 0 };

    
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status))
    {
        status = FltParseFileNameInformation(FileNameInfo);

        if (NT_SUCCESS(status))
        {

            if (FileNameInfo->Name.MaximumLength < 200)
            {
                RtlCopyMemory(Name, FileNameInfo->Name.Buffer, FileNameInfo->Name.MaximumLength);
                _wcsupr(Name);
                
                if (wcsstr(Name, L"OPENME") != NULL)
                {
                    KdPrint(("read file %ws", Name));
                    char* ioBuffer = NULL;
                    PMDL MdlAddress = Data->Iopb->Parameters.Read.MdlAddress;
                    ULONG Length = (ULONG)Data->Iopb->Parameters.Read.Length;
                    
                    if (NULL != MdlAddress)
                    {
                        // Don't expect chained MDLs this high up the stack
                        ASSERT(MdlAddress->Next == NULL);
                        ioBuffer = (char*)MmGetSystemAddressForMdlSafe(MdlAddress, NormalPagePriority);
                        KdPrint(("read file Mdl: %s", ioBuffer));
                    }
                    else
                    {
                        ioBuffer = (char*)Data->Iopb->Parameters.Read.ReadBuffer;

                        KdPrint(("readBuffer file: %s", ioBuffer));
                    }

                    if (ioBuffer != NULL)
                    {
                        //KdPrint(("read file: %s", ioBuffer));
                    }
                    else {
                        KdPrint(("read buffer is null"));
                    }
                    
                    char* str = "234";
                    RtlCopyMemory(Data->Iopb->Parameters.Read.ReadBuffer, str, 4);
                    Data->Iopb->Parameters.Read.Length = 4;
                }
            }
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);

    if (NT_SUCCESS(status))
    {

        status = FltStartFiltering(FilterHandle);

        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(FilterHandle);
        }
    }

    return status;
}