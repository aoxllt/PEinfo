package model

import "time"

var C = make(chan string)
var ResultChan = make(chan Info)
var Listlen int
var P = make(chan Pr)

// 机器架构映射表
var MachineMap = map[uint16]string{
	0x0000: "Unknown Machine",
	0x014c: "Intel 386",
	0x0162: "MIPS little-endian (R3000)",
	0x0166: "MIPS little-endian (R4000)",
	0x0168: "MIPS little-endian (R10000)",
	0x0169: "MIPS little-endian WCE v2",
	0x0184: "Alpha_AXP",
	0x01a2: "SH3 little-endian",
	0x01a3: "SH3 DSP",
	0x01a4: "SH3E little-endian",
	0x01a6: "SH4 little-endian",
	0x01a8: "SH5",
	0x01c0: "ARM Little-Endian",
	0x01c2: "ARM Thumb",
	0x01d3: "AM33",
	0x01F0: "IBM PowerPC Little-Endian",
	0x01f1: "PowerPC with Floating Point",
	0x0200: "Intel 64-bit (IA-64)",
	0x0266: "MIPS with FPU (MIPS16)",
	0x0284: "ALPHA64",
	0x0366: "MIPS with FPU",
	0x0466: "MIPS with FPU16",
	0x0520: "Infineon Tricore",
	0x0CEF: "Common Executable Format (CEF)",
	0x0EBC: "EFI Byte Code (EBC)",
	0x8664: "AMD64 (K8)",
	0x9041: "M32R little-endian",
	0xC0EE: "Common Language Runtime (CEE)",
}

type Pr struct {
	Pid  uint32
	Path string
}

var SubsystemMap = map[int]string{
	0:  "UNKNOWN",
	1:  "NATIVE",
	2:  "WINDOWS_GUI",
	3:  "WINDOWS_CUI",
	4:  "OS2_CUI",
	5:  "POSIX_CUI",
	6:  "NATIVE_WINDOWS",
	7:  "WINDOWS_CE_GUI",
	8:  "EFI_APPLICATION",
	9:  "EFI_BOOT_SERVICE_DRIVER",
	10: "EFI_RUNTIME_DRIVER",
	11: "EFI_ROM",
	12: "XBOX",
}

// 最终合并的数据
type Info struct {
	DosHeader     DosHeader
	NTHeader      NTHeader
	SectionHeader []SectionHeader
	ImportTable   ImportTable
	ExportTable   ExportTable
	ResourceTable ResourceTable
	Process       Process
	OtherInfo     OtherInfo
	F             []string
}

// Dos头
type DosHeader struct {
	EMagic    uint16     // 魔数
	ECblp     uint16     // 文件最后一页的字节数
	ECp       uint16     // 文件中的页数
	Ecrlc     uint16     // 重定位数量
	ECparhdr  uint16     // 头部的大小（以段为单位）
	EMinalloc uint16     // 文件所需的最小附加段数
	EMaxalloc uint16     // 文件所需的最大附加段数
	ESS       uint16     // 初始 SS 值
	ESP       uint16     // 初始 SP 值
	ECsum     uint16     // 校验和
	EIp       uint16     // 初始 IP 值
	Ecs       uint16     // 初始 CS 值
	ELfarlc   uint16     // 重定位表的文件地址
	EOvno     uint16     // 覆盖号
	ERes      [4]uint16  // 保留字段
	EOemid    uint16     // OEM 标识符
	EOeminfo  uint16     // OEM 信息
	ERes2     [10]uint16 // 保留字段
	ELfanew   int32      // 新的 EXE 头的文件地址
}

// NT头接口获取不同的类型的可选头
type NTHeader interface {
	GetFileHeader() FileHeader
	GetOptionalHeader() interface{}
}

// 32位NT头
type NTHeader32 struct {
	Signature      uint32         // PE 文件的签名 "PE\0\0"
	FileHeader     FileHeader     //文件头
	OptionalHeader OptionHeader32 //32位可选头
}

// 64位NT头
type NTHeader64 struct {
	Signature      uint32         // PE 文件的签名 "PE\0\0"
	FileHeader     FileHeader     //文件头
	OptionalHeader OptionHeader64 //64位可选头
}

// 文件头（通用）
type FileHeader struct {
	Machine              uint16 // 机器类型
	NumberOfSections     uint16 // 区段数量
	TimeDateStamp        uint32 // 时间戳
	PointerToSymbolTable uint32 // 符号表地址
	NumberOfSymbols      uint32 // 符号表数量
	SizeOfOptionalHeader uint16 // 可选头大小
	Characteristics      uint16 // 文件特性
}

// 32位可选头
type OptionHeader32 struct {
	Magic                       uint16 // 魔数，标识 PE 文件类型
	MajorLinkerVersion          byte   // 连接器主版本号
	MinorLinkerVersion          byte   // 连接器次版本号
	SizeOfCode                  uint32 // 代码段的大小
	SizeOfInitializedData       uint32 // 初始化数据段的大小
	SizeOfUninitializedData     uint32 // 未初始化数据段的大小
	AddressOfEntryPoint         uint32 // 程序入口地址
	BaseOfCode                  uint32 // 代码段基地址
	BaseOfData                  uint32
	ImageBase                   uint32            // 映像基地址
	SectionAlignment            uint32            // 区段对齐方式
	FileAlignment               uint32            // 文件对齐方式
	MajorOperatingSystemVersion uint16            // 操作系统主版本号
	MinorOperatingSystemVersion uint16            // 操作系统次版本号
	MajorImageVersion           uint16            // 映像主版本号
	MinorImageVersion           uint16            // 映像次版本号
	MajorSubsystemVersion       uint16            // 子系统主版本号
	MinorSubsystemVersion       uint16            // 子系统次版本号
	Win32VersionValue           uint32            // Win32 版本号
	SizeOfImage                 uint32            // 映像文件大小
	SizeOfHeaders               uint32            // 头部大小
	CheckSum                    uint32            // 文件校验和
	Subsystem                   uint16            // 子系统类型
	DllCharacteristics          uint16            // DLL 特性
	SizeOfStackReserve          uint32            // 堆栈保留大小（64 位）
	SizeOfStackCommit           uint32            // 堆栈提交大小（64 位）
	SizeOfHeapReserve           uint32            // 堆保留大小（64 位）
	SizeOfHeapCommit            uint32            // 堆提交大小（64 位）
	LoaderFlags                 uint32            // 加载器标志
	NumberOfRvaAndSizes         uint32            // 数据目录项数量
	DataDirectory               [16]DataDirectory // 数据目录
}

// 64位可选头
type OptionHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory // 数据目录
}

// 数据目录
type DataDirectory struct {
	VirtualAddress uint32 // 数据目录的虚拟地址
	Size           uint32 // 数据目录的大小
}

// 节区头
type SectionHeader struct {
	Name                 [8]byte // 节区名称
	VirtualSize          uint32  // 节区的虚拟大小
	VirtualAddress       uint32  // 节区的虚拟地址
	SizeOfRawData        uint32  // 节区的原始数据大小（文件中的大小）
	PointerToRawData     uint32  // 原始数据的指针（相对于文件开始的位置）
	PointerToRelocations uint32  // 重定位表的指针
	PointerToLinenumbers uint32  // 行号表的指针
	NumberOfRelocations  uint16  // 重定位数量
	NumberOfLinenumbers  uint16  // 行号数量
	Characteristics      uint32  // 节区特性（如可执行、可写等）
}

// 其他可读信息
type OtherInfo struct {
	Bit              string //文件位数
	FileSize         string
	Subsystem        string
	Machineinfo      string    //设备类型
	CreateTime       time.Time //创建时间（YYYY-MM-DD）
	ConnectorVersion string    //连接器版本
	OsVersion        string    //系统版本
	ImageVersion     string    //image版本
}

// 导入表信息
type ImportTable struct {
	DllName []string
}

// 导入表32位
type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics uint32 // 0 表示终止空的导入描述符，或者是指向原始未绑定 IAT 的 RVA（相对虚拟地址）
	TimeDateStamp   uint32 // 时间戳，表示导入的时间
	ForwarderChain  uint32 // 如果没有转发器，值为 -1
	Name            uint32 // DLL 名称的 RVA（相对虚拟地址）
	FirstThunk      uint32 // IAT 的 RVA（如果已绑定，这个 IAT 包含实际的地址）
}

// 导入表64位
type IMAGE_IMPORT_DESCRIPTOR64 struct {
	Characteristics    uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint64
	FirstThunk         uint64
	OriginalFirstThunk uint64
}

// 导出表信息
type ExportTable struct {
	Name string           //dll名
	Func []ExportFunction //导出方法
}

// 方法
type ExportFunction struct {
	Name string //方法名
	Addr uint32 //调用地址
}

// 导出表
type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// 资源表信息
type ResourceTable struct {
	Entry Entry
}

// 资源目录
type IMAGE_RESOURCE_DIRECTORY struct {
	Characteristics      uint32 // 属性，一般为0
	TimeDateStamp        uint32 // 资源的产生时刻，一般为0
	MajorVersion         uint16 // 主版本号，一般为0
	MinorVersion         uint16 // 次版本号，一般为0
	NumberOfNamedEntries uint16 // 以名称（字符串）命名的资源数量
	NumberOfIdEntries    uint16 // 以ID（整型数字）命名的资源数量
}

// 目录项
type IMAGE_RESOURCE_DIRECTORY_ENTRY struct {
	Name         uint32
	OffsetToData uint32
}

// 资源分类
type Entry struct {
	Cursor        []Tmp // 光标（Cursor）资源条目
	Bitmap        []Tmp // 位图（Bitmap）资源条目
	Icon          []Tmp // 图标（Icon）资源条目
	Menu          []Tmp // 菜单（Menu）资源条目
	Dialog        []Tmp // 对话框（Dialog）资源条目
	String        []Tmp // 字符串（String）资源条目
	FontDirectory []Tmp // 字体目录（Font Directory）资源条目
	Font          []Tmp // 字体（Font）资源条目
	Accelerators  []Tmp // 加速键（Accelerators）资源条目
	Unformatted   []Tmp // 未格式化资源（Unformatted）资源条目
	MessageTable  []Tmp // 消息表（MessageTable）资源条目
	GroupCursor   []Tmp // 组光标（Group Cursor）资源条目
	GroupIcon     []Tmp // 图标组（Group Icon）资源条目
	VersionInfo   []Tmp // 版本信息（Version Information）资源条目
}

// 字符串名称结构
type IMAGE_RESOURCE_DIR_STRING_U struct {
	Length     uint16 // WORD 类型，字符串长度
	NameString []uint16
}

// 资源数据表
type IMAGE_RESOURCE_DATA_ENTRY struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

// 暂存结构
type Tmp struct {
	Name     string
	Fileaddr int64
	Size     uint32
	Content  []byte
}

type Process struct {
	Processname []string
	Pid         []int32
}

func (n *NTHeader32) GetFileHeader() FileHeader {
	return n.FileHeader
}

func (n *NTHeader32) GetOptionalHeader() interface{} {
	return n.OptionalHeader
}

func (n *NTHeader64) GetFileHeader() FileHeader {
	return n.FileHeader
}

func (n *NTHeader64) GetOptionalHeader() interface{} {
	return n.OptionalHeader
}
