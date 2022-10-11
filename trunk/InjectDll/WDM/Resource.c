#include "Resource.h"
#include "..\libdrv\inc\lib.h"


UNICODE_STRING g_DllDosFullPath;//被注入DLL的全路径(DOS格式)。
UNICODE_STRING g_DllDosFullPathWow64;


PUNICODE_STRING g_RegistryPath;


//BOOLEAN create_dll_XXX(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName) //CONST
//    /*
//    参数的形式是："\Device\HarddiskVolume1\XXX或者\\??\\c:\\WINDOWS\\system32\\config\\SAM。
//
//    功能：复制独占式的和被锁定（ZwLockFile）的文件。
//
//    说明：
//    1.IoCreateFileEx函数有IO_IGNORE_SHARE_ACCESS_CHECK功能，可是This routine is available starting with Windows Vista.
//    2.由于专门复制被独占式使用的文件，如分页文件（正在使用的pagefile.sys）和各种被正在使用HIVE文件.
//    3.扩展功能：如删除文件（打开的时候带有删除的属性：FILE_DELETE_ON_CLOSE ）估计也可以的，这个不用发送IRP，至少在形式上。
//
//    存在的缺点有:
//    1.没有复制文件的属性,如:文件的所有者等信息.
//    */
//{
//    BOOLEAN b = FALSE;
//    NTSTATUS status = STATUS_UNSUCCESSFUL;
//    OBJECT_ATTRIBUTES ob;
//    HANDLE FileHandle = 0;
//    HANDLE DestinationFileHandle = 0;
//    IO_STATUS_BLOCK  IoStatusBlock = {0};
//    PVOID Buffer = 0;
//    SIZE_T Length = 0;
//    ULONG CreateDisposition = 0;
//    FILE_STANDARD_INFORMATION fsi = {0};
//    LARGE_INTEGER ByteOffset = {0};
//    LARGE_INTEGER AllocationSize = {0};
//    LARGE_INTEGER file_size = {0};
//    FILE_FULL_EA_INFORMATION ffai = {0};
//    HANDLE SectionHandle = 0;
//    PVOID BaseAddress = 0;
//    SIZE_T ViewSize = 0;
//    int i;
//    PVOID BaseAddress2 = 0;
//    PVOID p;
//
//    InitializeObjectAttributes(&ob, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
//    //status = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
//    //if (!NT_SUCCESS (status)) 
//    //{
//    //    //KdPrint(("ZwOpenFile fail with 0x%x.\n", status));
//    //    if ( status == STATUS_OBJECT_NAME_NOT_FOUND)  {
//    //        KdPrint(("file does not exist\n"));
//    //    }
//    //    if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST ) {
//    //        KdPrint(("file does not exist\n"));
//    //    }
//    //    return b;
//    //}
//    status = IoCreateFileSpecifyDeviceObjectHint(&FileHandle,
//                                                 GENERIC_READ | SYNCHRONIZE,
//                                                 &ob,
//                                                 &IoStatusBlock,
//                                                 &AllocationSize,
//                                                 FILE_ATTRIBUTE_NORMAL,
//                                                 /*
//                                                 Specifies the type of share access to the file that the caller would like, as zero, or one, or a combination of the following flags.
//                                                 To request exclusive access, set this parameter to zero.
//                                                 If the IO_IGNORE_SHARE_ACCESS_CHECK flag is specified in the Options parameter, the I/O manager ignores this parameter.
//                                                 However, the file system might still perform access checks.
//                                                 Thus, it is important to specify the sharing mode you would like for this parameter, even when using the IO_IGNORE_SHARE_ACCESS_CHECK flag.
//                                                 For the greatest chance of avoiding sharing violation errors, specify all of the following share access flags.
//                                                 */
//                                                 FILE_SHARE_VALID_FLAGS,
//                                                 FILE_OPEN,
//                                                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
//                                                 &ffai,
//                                                 sizeof(FILE_FULL_EA_INFORMATION),
//                                                 CreateFileTypeNone,//其实命名管道和邮件槽也定义了。
//                                                 NULL,
//                                                 /*
//                                                 Indicates that the I/O manager should not perform share-access checks on the file object after it is created.
//                                                 However, the file system might still perform these checks.
//                                                 */
//                                                 IO_IGNORE_SHARE_ACCESS_CHECK,
//                                                 /*
//                                                 A pointer to the device object to which the create request is to be sent.
//                                                 The device object must be a filter or file system device object in the file system driver stack for the volume on which the file or directory resides.
//                                                 This parameter is optional and can be NULL. If this parameter is NULL, the request will be sent to the device object at the top of the driver stack.
//                                                 */
//                                                 NULL
//    );
//    if (!NT_SUCCESS(status)) {
//        //KdPrint(("ZwOpenFile fail with 0x%x.\n", status));
//        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
//            KdPrint(("file does not exist\n"));
//        }
//        if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
//            KdPrint(("file does not exist\n"));
//        }
//        return b;
//    }
//
//    //可以考虑在这里给文件加锁,保护,不让别的操作再写入.ZwLockFile,再在适当的时候解锁:ZwUnlockFile.
//    //可是This routine is available in Windows 7 and later versions of the Windows operating system.
//    //不过NtLockFile和NtUnlockFile在XP下导出，可以使用。
//
//    status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
//    if (!NT_SUCCESS(status)) {
//        KdPrint(("ZwQueryInformationFile fail with 0x%x.\n", status));
//        ZwClose(FileHandle);
//        return b;;
//    }
//
//    //新建文件.
//    CreateDisposition = FILE_OVERWRITE_IF;
//    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
//    status = ZwCreateFile(&DestinationFileHandle,
//                          FILE_ALL_ACCESS | SYNCHRONIZE,
//                          &ob,
//                          &IoStatusBlock,
//                          &AllocationSize,
//                          FILE_ATTRIBUTE_NORMAL,
//                          FILE_SHARE_WRITE,
//                          CreateDisposition,
//                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
//                          NULL,
//                          0);
//    if (!NT_SUCCESS(status)) {
//        //KdPrint(("ZwCreateFile fail with 0x%x.\n", status));
//        ZwClose(FileHandle);
//        if (status == STATUS_OBJECT_NAME_COLLISION) {//-1073741771 ((NTSTATUS)0xC0000035L) Object Name already exists.
//            b = TRUE;
//        }
//        return b;
//    }
//
//    //文件大小为零，就结束了。
//    if (fsi.EndOfFile.QuadPart == 0) {
//        ZwClose(FileHandle);
//        ZwClose(DestinationFileHandle);
//        return TRUE;
//    }
//
//    //不处理大于4G的文件。
//    if (fsi.EndOfFile.HighPart != 0) {
//        ZwClose(FileHandle);
//        ZwClose(DestinationFileHandle);
//        return TRUE;
//    }
//
//    file_size = fsi.EndOfFile;
//    //Length = PAGE_SIZE;//测试专用。
//    //Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);//Length == 0时加驱动验证器，这里会蓝屏。
//    //if (Buffer == NULL) { 
//    //    status = STATUS_UNSUCCESSFUL;
//    //    DbgPrint("发生错误的文件为:%s, 代码行为:%d\n", __FILE__, __LINE__);
//    //    ZwClose(FileHandle);
//    //    ZwClose(DestinationFileHandle);
//    //    return b;
//    //}
//
//    InitializeObjectAttributes(&ob, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);//绝对不可以在这里设置路径。
//    status = ZwCreateSection(&SectionHandle,
//                             SECTION_MAP_READ | SECTION_QUERY,
//                             &ob,
//                             &fsi.EndOfFile,
//                             PAGE_READONLY,
//                             SEC_COMMIT,
//                             FileHandle);
//    if (!NT_SUCCESS(status)) {
//        KdPrint(("ZwCreateSection fail with 0x%x.\n", status));
//        //ExFreePoolWithTag(Buffer, TAG);
//        ZwClose(FileHandle);
//        ZwClose(DestinationFileHandle);
//        return b;
//    }
//
//    /*
//    本想一页数据一页数据的读取的。
//    现在是整个全部读取了。
//    */
//    //for ( ;ByteOffset.QuadPart < file_size.QuadPart ; ) 
//    {
//        ULONG_PTR ResourceIdPath[3];
//        PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = NULL;
//        PVOID  MessageData;
//        ULONG Size = 0;
//
//        //RtlZeroMemory(Buffer, Length);
//
//        //status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &ByteOffset, NULL);
//        //if (!NT_SUCCESS (status)) //对于带锁的文件的打开会失败。
//        //{
//        //    KdPrint(("ZwReadFile fail with 0x%x.\n", status));
//        //    ExFreePoolWithTag(Buffer, TAG);
//        //    ZwClose(FileHandle);
//        //    ZwClose(DestinationFileHandle);
//        //    return b;
//        //}
//
//        //注意：这里的权限和上面的权限要对应。
//        status = ZwMapViewOfSection(SectionHandle,
//                                    ZwCurrentProcess(),
//                                    &BaseAddress,
//                                    0,
//                                    0,
//                                    NULL,
//                                    &ViewSize,
//                                    ViewShare,
//                                    0,
//                                    PAGE_READONLY);
//        if (!NT_SUCCESS(status)) {
//            KdPrint(("ZwMapViewOfSection fail with 0x%x.\n", status));
//            //ExFreePoolWithTag(Buffer, TAG);
//            ZwClose(SectionHandle);
//            ZwClose(FileHandle);
//            ZwClose(DestinationFileHandle);
//            return b;
//        }
//
//        i = *(int *)BaseAddress;
//        BaseAddress2 = GetImageBase("test.sys");//上面的ZwMapViewOfSection等几个函数是没有用的。
//
//        //获取DLL的内容。
//        //ResourceDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)ExAllocatePoolWithTag( NonPagedPool, fsi.EndOfFile.LowPart, TAG);//ntdll.dll中的LdrFindResource_U函数的这个函数需要申请，否则异常。
//        //ASSERT(ResourceDataEntry);
//        //RtlZeroMemory(ResourceDataEntry, fsi.EndOfFile.LowPart);
//        ResourceIdPath[0] = 10;//RT_RCDATA RCDATA 10
//        ResourceIdPath[1] = 0x1391;//0x1391 == 5009
//        ResourceIdPath[2] = 0;
//        status = LdrFindResource_U(BaseAddress2, ResourceIdPath, 3, &ResourceDataEntry);//用ZwMapViewOfSection返回c000008a
//        ASSERT(NT_SUCCESS(status));
//        status = LdrAccessResource(BaseAddress2, ResourceDataEntry, &MessageData, &Size);
//        ASSERT(NT_SUCCESS(status));
//
//        //如果要处理大于4G的数据请加个循环。不过大于4G的数据也很难映射成功。
//        status = ZwWriteFile(DestinationFileHandle, NULL, NULL, NULL, &IoStatusBlock, MessageData, Size, &ByteOffset, NULL);
//        if (!NT_SUCCESS(status)) {
//            KdPrint(("ZwWriteFile fail with 0x%x.\n", status));
//            ExFreePoolWithTag(ResourceDataEntry, TAG);
//            //ExFreePoolWithTag(Buffer, TAG);
//            ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
//            ZwClose(SectionHandle);
//            ZwClose(FileHandle);
//            ZwClose(DestinationFileHandle);
//            return b;
//        }
//
//        //ByteOffset.QuadPart += IoStatusBlock.Information;
//
//        //ExFreePoolWithTag(ResourceDataEntry, TAG );//这个不需要释放，否则蓝屏。用法见：ExpInitializeExecutive函数源码。
//        ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
//    }
//
//    //ExFreePoolWithTag(Buffer, TAG);
//    ZwClose(SectionHandle);
//    ZwClose(FileHandle);
//    ZwClose(DestinationFileHandle);
//
//    return TRUE;
//}


void BuildDLL()
{
    UNICODE_STRING SystemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot"); 
    UNICODE_STRING SystemRootNtPath = {0};
    UNICODE_STRING SystemRootDosPath = {0};
    GetSystemRootName(&SystemRoot, &SystemRootNtPath, &SystemRootDosPath);

    UNICODE_STRING DllNtFullPath = {0};    
    UNICODE_STRING Dll = RTL_CONSTANT_STRING(L"\\System32\\hook.dll");
    DllNtFullPath.MaximumLength = SystemRootNtPath.MaximumLength + Dll.MaximumLength;
    NTSTATUS Status = AllocateUnicodeString(&DllNtFullPath);
    ASSERT(NT_SUCCESS(Status));
    RtlCopyUnicodeString(&DllNtFullPath, &SystemRootNtPath);
    ASSERT(NT_SUCCESS(Status));
    Status = RtlAppendUnicodeStringToString(&DllNtFullPath, &Dll);
    ASSERT(NT_SUCCESS(Status));

    g_DllDosFullPath.MaximumLength = SystemRootDosPath.MaximumLength + Dll.MaximumLength;
    Status = AllocateUnicodeString(&g_DllDosFullPath);
    ASSERT(NT_SUCCESS(Status));
    RtlCopyUnicodeString(&g_DllDosFullPath, &SystemRootDosPath);
    ASSERT(NT_SUCCESS(Status));
    Status = RtlAppendUnicodeStringToString(&g_DllDosFullPath, &Dll);
    ASSERT(NT_SUCCESS(Status));

    /*
    可以把把DLL内嵌在SYS的资源里面，然后用：LdrFindResource_U/LdrAccessResource/LdrEnumResources等函数获取，然后在ZwCreateFile一个。
    */

#ifdef _WIN64
    UNICODE_STRING DllWow64 = RTL_CONSTANT_STRING(L"\\SysWOW64\\hook.dll");

    UNICODE_STRING DllNtFullPathWow64 = {0};
    DllNtFullPathWow64.MaximumLength = SystemRootNtPath.MaximumLength + DllWow64.MaximumLength;
    Status = AllocateUnicodeString(&DllNtFullPathWow64);
    ASSERT(NT_SUCCESS(Status));
    RtlCopyUnicodeString(&DllNtFullPathWow64, &SystemRootNtPath);
    ASSERT(NT_SUCCESS(Status));
    Status = RtlAppendUnicodeStringToString(&DllNtFullPathWow64, &DllWow64);
    ASSERT(NT_SUCCESS(Status));

    g_DllDosFullPathWow64.MaximumLength = SystemRootDosPath.MaximumLength + DllWow64.MaximumLength;
    Status = AllocateUnicodeString(&g_DllDosFullPathWow64);
    ASSERT(NT_SUCCESS(Status));
    RtlCopyUnicodeString(&g_DllDosFullPathWow64, &SystemRootDosPath);
    ASSERT(NT_SUCCESS(Status));
    Status = RtlAppendUnicodeStringToString(&g_DllDosFullPathWow64, &DllWow64);
    ASSERT(NT_SUCCESS(Status));
#endif  
    
#ifdef _WIN64
    ExtraFile("test.sys", RT_RCDATA, 5009, &DllNtFullPath);
    ExtraFile("test.sys", RT_RCDATA, 5010, &DllNtFullPathWow64);
#else
    ExtraFile("test.sys", RT_RCDATA, 5010, &DllNtFullPath);
#endif    

    FreeUnicodeString(&DllNtFullPath);
    FreeUnicodeString(&SystemRootNtPath);
    FreeUnicodeString(&SystemRootDosPath);

#ifdef _WIN64
    FreeUnicodeString(&DllNtFullPathWow64);
#endif  
}
