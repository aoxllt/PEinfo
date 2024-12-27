package Dllinject

import (
	"fmt"
	"syscall"
	"unsafe"
)

func init() {

}

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	ntdll              = syscall.NewLazyDLL("ntdll.dll")
	openProcess        = kernel32.NewProc("OpenProcess")
	virtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
	createRemoteThread = kernel32.NewProc("CreateRemoteThread")
	getProcAddress     = kernel32.NewProc("GetProcAddress")
	getModuleHandle    = kernel32.NewProc("GetModuleHandleA")
	loadLibrary        = kernel32.NewProc("LoadLibraryA")
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
	MEM_COMMIT         = 0x1000
	MEM_RESERVE        = 0x2000
	PAGE_READWRITE     = 0x04
	THREAD_ALL_ACCESS  = 0x1F03FF
)

// injectDLL 实现 DLL 注入
func InjectDLL(processID uint32, dllPath string) error {
	// 打开目标进程
	hProcess, _, err := openProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(processID))
	if hProcess == 0 {
		return fmt.Errorf("打开进程失败: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	// 为 DLL 路径分配内存
	dllPathBytes := []byte(dllPath + "\x00")
	dllPathLen := uintptr(len(dllPathBytes))
	remoteMemory, _, err := virtualAllocEx.Call(hProcess, 0, dllPathLen, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
	if remoteMemory == 0 {
		return fmt.Errorf("在目标进程中分配内存失败: %v", err)
	}

	// 将 DLL 路径写入目标进程的内存
	_, _, err = writeProcessMemory.Call(hProcess, remoteMemory, uintptr(unsafe.Pointer(&dllPathBytes[0])), dllPathLen, 0)
	if err != nil && err.Error() != "操作成功完成。" {
		return fmt.Errorf("写入内存失败: %v", err)
	}

	// 获取 `LoadLibraryA` 的地址
	kernel32Handle, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringBytePtr("kernel32.dll"))))
	loadLibraryAddr, _, err := getProcAddress.Call(kernel32Handle, uintptr(unsafe.Pointer(syscall.StringBytePtr("LoadLibraryA"))))
	if loadLibraryAddr == 0 {
		return fmt.Errorf("获取 LoadLibraryA 地址失败: %v", err)
	}

	// 在目标进程中创建远程线程，执行 `LoadLibraryA` 来加载 DLL
	hThread, _, err := createRemoteThread.Call(hProcess, 0, 0, loadLibraryAddr, remoteMemory, 0, 0)
	if hThread == 0 {
		return fmt.Errorf("创建远程线程失败: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hThread))

	// 等待线程执行完成
	syscall.WaitForSingleObject(syscall.Handle(hThread), syscall.INFINITE)

	fmt.Println("DLL 注入成功！")
	return nil
}
