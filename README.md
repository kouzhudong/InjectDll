# InjectDll
Inject dll to process in driver  

本来是叫用APC的机制在驱动注入应用层DLL到应用层的工程。  
发现APC有很多缺点，不容易控制，如：触发，因而导致不支持卸载。  
还有函数未公开，尽管导出了。  
唯一的优点：系统的机制，不会轻易被干掉。  

其实内核也可以创建进程的，从XP都有这个函数，且导出了，只不过后来变为以序数的形式导出的，而非导出名字了。  

你我期望的注入的特点：  
1. 无硬编码，无特征码。  
2. 不使用汇编（包括机器码，shellcode等）。  
3. 不申请应用层的内存，特别是可执行的。  
   那思路是搜索PE的可写间隙。  
4. 可卸载。  
   是指驱动，而非被注入的DLL。  
   其实，被注入的DLL可卸载会更简单。不用暴力的遍历进程强制卸载，只需DLL留一个可卸载的IPC接口即可。  
5. 支持WOW64.  
6. 尽可能多的注入。  
   排除没有用户态的进程（Minimal processes，如：Secure System, Registry, System Idle Process, System, Interrrupts, Memory Compression等）  
   Pico processes（如：WSL1.0）不支持。  
   保护进程（Protected processes）也不建议注入，尽管也可以强制注入（用一些猥亵的手段）。  
   Native processes（即只准有Ntdll.dll和自身的进程）也不建议注入（本方案按不支持）。
   但是.net(APP),Java等进程还是不放过的。  
   挂起状态的进程不支持。
7. 其他。如：优化，快速，防止多次注入等。  

被注入的DLL的功能在乎你的想象，如：加入HOOK引擎（如微软的Detours）。  
