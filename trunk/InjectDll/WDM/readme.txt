功能：在驱动层注入DLL到应用层。

其实注入线程和shellcode最隐蔽。
但是注入DLL最简单方便。

在驱动层运行应用层的代码，最好的办法是注入。

在驱动层某些功能是不能拦截不到的，有不易hook.所以最好在应用层hook.
但应用层也不是所有的功能都支持hook的，所以要自己Hook.

最标准和权威的hook是微软的那个Hook库。


--------------------------------------------------------------------------------------------------


APC是操作系统的一项基本的机制。
所以不用考虑和担心，微软未来会移除这个功能。
因为要兼容，所以微软也不会（轻易）改变接口。

在应用层微软公开的APC的接口，但驱动没有，但是驱动导出了。
所以有此文。

此文有很好的兼容性，从XP，2003支持所有的以后的操作系统。
尽管VISTA及以后在内核提供了创建用户态的线程的函数。


--------------------------------------------------------------------------------------------------


注入第一要素是稳定，宁肯失败也不要出问题。
有很多进程是注定要失败的。
如：
1. Protected processes。
  详细见：Protected Process Light (PPL)。
  这类进程是打不开，尽管是在驱动（常规情况）。
2. Minimal processes。
  这类进程是没有用户态空间的。
  举例：System process and Memory Compression process，还有注册表，中断，IDLE等。
  尽管你可以申请用户态的内存，但，这也没有比较注入，除非你想隐藏功能。
3. .net(app)和java等程序，这个要考虑要不要注入。
4. Pico processes。
  如：WSL的进程。还是放过吧！
5. X64下对于WOW64进程（建议）要注入32的DLL。
6. Native processes。
  这类程序只有Ntdll.dll和自身。
  这类程序平常下不可启动，只有在操作系统启动时启动。如：检查磁盘的那个，还有会话管理器进程。
7. 还包括第三方保护的进程，如：杀软，调试等。

因为：注入第一要素是稳定，宁肯失败也不要出问题。
所以：
1.不检查线程的状态。
2.不检查注入的结果。
3.忽略一些进程。
4.有可能会导致内存泄露（因为有的APC会永远不会被执行）。
5.最好不支持卸载，因为在开启驱动校验器下，内存泄露会导致蓝屏。
  还有一个原因是不知APC会被何时触发，如果驱动卸载后，又触发APC，会导致APC的内核回调被调用（如：本驱动的PspQueueApcSpecialApc）。
  但，此时驱动已经卸载，所以会方位无效的内存而蓝屏。


--------------------------------------------------------------------------------------------------


在Windows 10下测试会出现：

******************************************************************
* This break indicates this binary is not signed correctly: \Device\HarddiskVolume4\Windows\System32\dll.dll
* and does not meet the system policy.
* The binary was attempted to be loaded in the process: \Device\HarddiskVolume4\Windows\System32\csrss.exe
* This is not a failure in CI, but a problem with the failing binary.
* Please contact the binary owner for getting the binary correctly signed.
******************************************************************
Break instruction exception - code 80000003 (first chance)
CI!CipReportAndReprieveUMCIFailure+0x563:
fffff807`7d6215d7 cc              int     3

此时，这个DLL已经签名，且是双签名（SHA1+SHA256），还提示签名不正确，难道要有微软的签名？还是要别的策略配置？

0: kd> kv 
 # Child-SP          RetAddr           : Args to Child                                                           : Call Site
00 ffffc987`f2852f90 fffff807`7d61d2e7 : ffff880e`7635104b 00000000`00000000 ffff880e`7e94c9d0 00000000`00000000 : CI!CipReportAndReprieveUMCIFailure+0x563
01 ffffc987`f28530d0 fffff807`7cb3e4b6 : ffffc987`f2853320 fffff807`7bf40000 00000000`0000000f fffff807`7bf40000 : CI!CiValidateImageHeader+0xce7
02 ffffc987`f2853260 fffff807`7cb3dfda : 00000000`00000000 00000000`00000001 00000000`00000000 00000000`0009b000 : nt!SeValidateImageHeader+0xd6
03 ffffc987`f2853310 fffff807`7cb1e33f : ffffc987`f2853800 00000000`00000000 00000000`00000000 ffffc987`f2853660 : nt!MiValidateSectionCreate+0x436
04 ffffc987`f2853500 fffff807`7cb4f5f8 : ffffc987`f2853840 ffffc987`f2853840 ffffc987`f2853660 ffffb802`13105160 : nt!MiValidateSectionSigningPolicy+0x97
05 ffffc987`f2853560 fffff807`7caca070 : ffff880e`7e94c9d0 ffffc987`f2853840 ffffc987`f2853840 ffff880e`7e94c9a0 : nt!MiCreateNewSection+0x674
06 ffffc987`f28536d0 fffff807`7caca374 : ffffc987`f2853700 ffffb802`13105160 ffff880e`7e94c9d0 00000000`00000000 : nt!MiCreateImageOrDataSection+0x2d0
07 ffffc987`f28537c0 fffff807`7cac99cf : 00000000`01000000 ffffc987`f2853b80 00000000`00000001 00000000`00000010 : nt!MiCreateSection+0xf4
08 ffffc987`f2853940 fffff807`7cac9760 : 000000f4`3273ed58 00000000`0000000d 00000000`00000000 00000000`00000001 : nt!MiCreateSectionCommon+0x1ff
09 ffffc987`f2853a20 fffff807`7c691358 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!NtCreateSection+0x60
0a ffffc987`f2853a90 00007ff8`8051d6d4 : 00007ff8`804ad4ea 00000262`5f615c10 000000f4`3273ee50 000000f4`3273ee50 : nt!KiSystemServiceCopyEnd+0x28 (TrapFrame @ ffffc987`f2853b00)
0b 000000f4`3273ed08 00007ff8`804ad4ea : 00000262`5f615c10 000000f4`3273ee50 000000f4`3273ee50 00000000`00000030 : ntdll!NtCreateSection+0x14
0c 000000f4`3273ed10 00007ff8`804ae588 : 00000000`00000000 000000f4`3273ee50 00000262`5f615c68 00000262`5f61d9c0 : ntdll!LdrpMapDllNtFileName+0x136
0d 000000f4`3273ee10 00007ff8`804ae2e0 : 000000f4`3273f048 00000262`5f61d9c0 000000f4`3273f001 000000f4`3273f048 : ntdll!LdrpMapDllFullPath+0xe0
0e 000000f4`3273efa0 00007ff8`804a24b6 : 00000262`5f61d9c0 000000f4`3273f101 000000f4`00000000 000000f4`3273f0d0 : ntdll!LdrpProcessWork+0x74
0f 000000f4`3273f000 00007ff8`804a2228 : 000000f4`3273f0d0 000000f4`3273f270 000000f4`3273f360 000000f4`3273f260 : ntdll!LdrpLoadDllInternal+0x13e
10 000000f4`3273f080 00007ff8`804a16e4 : 00000000`00000000 00000000`00000001 00007ff8`7e13b42d 00007ff8`804a5021 : ntdll!LdrpLoadDll+0xa8
11 000000f4`3273f230 00007ff8`7e2ae9c0 : 00006533`f23782bc 00000000`00000000 00000262`5f61ffe0 00007ff8`8056fd23 : ntdll!LdrLoadDll+0xe4
12 000000f4`3273f320 00000262`615a0042 : 00000262`00000000 00000000`00000001 00000000`00000000 00000000`00000000 : kernelbase!LoadLibraryExW+0x170
13 000000f4`3273f390 00000262`00000000 : 00000000`00000001 00000000`00000000 00000000`00000000 00000262`61590000 : 0x00000262`615a0042
14 000000f4`3273f398 00000000`00000001 : 00000000`00000000 00000000`00000000 00000262`61590000 00000000`00001000 : 0x00000262`00000000
15 000000f4`3273f3a0 00000000`00000000 : 00000000`00000000 00000262`61590000 00000000`00001000 00000001`0000000a : 0x1


--------------------------------------------------------------------------------------------------


驱动中注入DLL/线程/shellcode的另外的思路：
1.RtlCreateUserThread
2.NtCreateThreadEx/ZwCreateThreadEx
3.KeUserModeCallBack
4.劫持线程的上下文。
5.加载PE时篡改PE的IAT。


--------------------------------------------------------------------------------------------------


1: kd> g
SXS: BasepCreateActCtx() Calling csrss server failed. Status = 0xc0000005


 *** An Access Violation occurred in wininit.exe:

The instruction at 00000000777A0DF4 tried to read from a NULL pointer

 *** enter .exr 0000000000A6E970 for the exception record
 ***  enter .cxr 0000000000A6E480 for the context
 *** then kb to get the faulting stack

Break instruction exception - code 80000003 (first chance)
ntdll!RtlUnhandledExceptionFilter2+0x361:
0033:00000000`7782ef31 cc              int     3
2: kd> .exr 0000000000A6E970
ExceptionAddress: 00000000777a0df4 (ntdll!RtlFindActivationContextSectionString+0x0000000000000244)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000000
   Parameter[1]: 0000000000000000
Attempt to read from address 0000000000000000
2: kd> .cxr 0000000000A6E480
rax=0000000000000000 rbx=0000000000a6ee10 rcx=000007fffffd9000
rdx=0000000000000000 rsi=0000000000a6ee90 rdi=0000000000000003
rip=00000000777a0df4 rsp=0000000000a6eb90 rbp=0000000000a6ee58
 r8=0000000000000002  r9=0000000000a6ec98 r10=0000000000a6ed78
r11=0000000000a6edc8 r12=0000000000000002 r13=0000000000000000
r14=0000000000a6ec98 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
ntdll!RtlFindActivationContextSectionString+0x244:
0033:00000000`777a0df4 48833800        cmp     qword ptr [rax],0 ds:002b:00000000`00000000=????????????????
2: kd> kb
  *** Stack trace for last set context - .thread/.cxr resets it
 # RetAddr           : Args to Child                                                           : Call Site
00 00000000`777a0476 : 00000000`006e0000 00000000`00a6ed78 00000000`00000000 00000000`00000000 : ntdll!RtlFindActivationContextSectionString+0x244
01 00000000`777a011b : 00000000`00000002 00000000`00000000 00000000`00000000 00000000`00a6ee48 : ntdll!RtlDosApplyFileIsolationRedirection_Ustr+0x626
02 00000000`7779eb2b : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlDosApplyFileIsolationRedirection_Ustr+0x2cb
03 00000000`7786e03f : 00000000`00000000 00000000`00000000 00000000`777773c0 00000000`00000000 : ntdll!LdrpApplyFileNameRedirection+0x2cb
04 00000000`7785ad7d : 00000000`00000000 00000000`00000000 00000000`00a6f3e8 000007fe`fd39298d : ntdll!LdrpLoadDll+0xff
05 000007fe`fd37b39a : 00000000`00000000 00000000`00000000 00000000`001543e0 00000000`00000000 : ntdll!LdrLoadDll+0xed
06 00000000`777db3fb : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000002 : KernelBase!LoadLibraryExW+0x2a3
07 00000000`777d9d5a : 00000000`7778332d 00000000`00000005 00000000`00000000 00000000`7777aa20 : ntdll!KiUserApcDispatch+0x2b
08 00000000`7778332d : 00000000`00000005 00000000`00000000 00000000`7777aa20 00000000`7777aa20 : ntdll!ZwWaitForMultipleObjects+0xa
09 00000000`7766556d : 00000000`00000000 00000000`00000000 00000000`00000000 00000001`8af4f9a8 : ntdll!TppWaiterpThread+0x14d
0a 00000000`777c372d : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0xd
0b 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x1d

可以看到是
ntdll!RtlFindActivationContextSectionString+0x244:
0033:00000000`777a0df4 48833800        cmp     qword ptr [rax],0 ds:002b:00000000`00000000=????????????????
出的问题。
这个栈正是APC注入DLL的线程。

需要IDA分析，为何如此。


--------------------------------------------------------------------------------------------------


功能：驱动注入DLL。
手法：APC。
思路：开始的时候是自己在被注入的进程申请可执行的内存，然后驱动复制代码过去。
      后来改为，直接使用kernel32（包括WOW64的）的LoadLibraryExW函数。
      参数是DLL的全路径。

      DLL的全路径现在是申请的用户态的内存，没有可执行属性，也没有释放。
      改进的思路是搜索一段进程的可读可写的内存，如：PE文件（包括加载的DLL）的间隙。

      因为地址空间布局随机化(ASLR)是在操作系统启动的时候执行的，且启动之后KnownDlls(32)的地址在每个进程中都一样，
      所以获取kernel32（包括WOW64的）的LoadLibraryExW函数的任务不必在加载每个DLL的时机进行，可以放在驱动的入口。

      可以搞一个进程上下文，不必在进程回调中维护，加载DLL的回调也可以。
      为了释放进程上下文，还是得有进程回调。
      进程上下文的内容可以是否已经加载kernel32（包括WOW64的）的LoadLibraryExW函数，是否已经注入DLL等成员。

      加载kernel32（包括WOW64的）是，并非一定MAP好了，所以注入DLL要在加载kernel32（包括WOW64的）之后的某个DLL进行，
      或者以后的所有的DLL，而不必进行判断：时候已经注入了，因为DLL不会加载多份，顶多引用计数增加而已。


--------------------------------------------------------------------------------------------------


已经注入，且注入失败的，再次加载DLL时，因为Kernel32.dll已经加载过，监控不到，此时的处理。

