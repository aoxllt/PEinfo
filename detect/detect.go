package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/shirou/gopsutil/process"
	"io"
	"log"
	"os"
	"rev/model"
	"strconv"
	"time"
)

// Detect 函数用于解析文件并输出重要的 PE 文件信息
func Detect(filepath string) model.Info {
	var otherinfo model.OtherInfo
	var info model.Info
	info.F = ProcessFile(filepath)
	// 打开文件
	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("打开文件失败: %v\n", err)
		return info
	}
	defer file.Close()

	//简单检查是否是合格的pe文件
	istrue, dosHeader, fileHeader := checkPe(file)
	if !istrue {
		return info
	}

	//计算文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("获取文件信息失败: %v\n", err)
		return info
	}
	fileSize := fileInfo.Size()

	//获取dos头的信息
	dosInfo := dosheadInfo(dosHeader)

	if fileSize >= 1024*1024 { // 如果文件大于或等于 1MB
		otherinfo.FileSize = fmt.Sprintf("%.2f MB", float64(fileSize)/float64(1024*1024))
	} else {
		otherinfo.FileSize = fmt.Sprintf("%.2f KB", float64(fileSize)/float64(1024))
	}
	fmt.Printf("文件大小 (File Size): %d 字节\n", fileSize)

	//获取nt头的信息
	ntInfo := NTheadInfo(file, dosInfo, fileHeader)

	//原始信息转换成可读信息
	otherinfo.Machineinfo = getMachineName(ntInfo.GetFileHeader().Machine)
	otherinfo.CreateTime = time.Unix(int64(ntInfo.GetFileHeader().TimeDateStamp), 0).UTC()
	//调用可选头，获取节区表
	optionalHeader := ntInfo.GetOptionalHeader()
	sections, remainingSpace, err := getSections(file, ntInfo.GetFileHeader(), dosInfo)
	if err != nil {
		log.Println("获取节区信息失败:", err)
		return info
	}

	// 判断并类型断言，根据32位还是64位做不同解析
	switch h := optionalHeader.(type) {
	case model.OptionHeader32:
		otherinfo.Bit = "PE32"
		otherinfo.ConnectorVersion = fmt.Sprintf("%d.%d", h.MajorLinkerVersion, h.MinorLinkerVersion)
		otherinfo.OsVersion = fmt.Sprintf("%d.%d", h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion)
		otherinfo.ImageVersion = fmt.Sprintf("%d.%d", h.MajorImageVersion, h.MinorImageVersion)
		otherinfo.Subsystem = getSubsystemName(h.Subsystem)
		info.DosHeader = dosInfo
		info.NTHeader = ntInfo
		info.SectionHeader = sections
		info.SectionHeader = append(info.SectionHeader, model.SectionHeader{
			SizeOfRawData: uint32(remainingSpace),
		})
		info.ImportTable = getImportTable32(h, sections, file)
		info.ExportTable = getExportTable32(h, sections, file)
		info.ResourceTable = getsrc32(h, sections, file)
		info.OtherInfo = otherinfo
	case model.OptionHeader64:
		otherinfo.Bit = "PE64"
		otherinfo.ConnectorVersion = fmt.Sprintf("%d.%d", h.MajorLinkerVersion, h.MinorLinkerVersion)
		otherinfo.OsVersion = fmt.Sprintf("%d.%d", h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion)
		otherinfo.ImageVersion = fmt.Sprintf("%d.%d", h.MajorImageVersion, h.MinorImageVersion)
		otherinfo.Subsystem = getSubsystemName(h.Subsystem)
		info.DosHeader = dosInfo
		info.NTHeader = ntInfo
		info.SectionHeader = sections
		info.SectionHeader = append(info.SectionHeader, model.SectionHeader{
			SizeOfRawData: uint32(remainingSpace),
		})
		info.ImportTable = getImportTable64(h, sections, file)
		info.ExportTable = getExportTable64(h, sections, file)
		info.ResourceTable = getsrc64(h, sections, file)
		info.OtherInfo = otherinfo
	default:
		otherinfo.Bit = "unknown"
	}
	return info
}

func ProcessId() (pid []int32) {

	pids, _ := process.Pids()
	for _, p := range pids {
		pid = append(pid, p)
	}
	return pid
}

func ProcessName() (pname []string) {
	pids, _ := process.Pids()
	for _, pid := range pids {
		pn, _ := process.NewProcess(pid)
		pName, _ := pn.Name()
		pname = append(pname, pName)
	}
	return pname
}

// 检查是否是pe文件
func checkPe(file *os.File) (bool, []byte, []byte) {
	// 读取 DOS Header
	dosHeader := make([]byte, 64)
	_, err := file.Read(dosHeader)
	if err != nil {
		log.Printf("读取 DOS Header 失败: %v\n", err)
		return false, nil, nil
	}

	// 检查 MZ 签名
	magic := binary.LittleEndian.Uint16(dosHeader[:2])
	if magic != 0x5A4D { // 'MZ'
		log.Println("该文件不是有效的 PE 文件 (缺少 MZ 签名)")
		return false, nil, nil
	}

	lfaNew := binary.LittleEndian.Uint32(dosHeader[0x3C:]) // PE 头偏移量

	// 跳转到 PE Header
	file.Seek(int64(lfaNew), 0)
	fileHeader := make([]byte, 24)
	_, err = file.Read(fileHeader)
	if err != nil {
		log.Printf("读取 PE Header 失败: %v\n", err)
		return false, nil, nil
	}

	// 检查 PE 签名
	if string(fileHeader[:4]) != "PE\x00\x00" {
		log.Println("该文件不是有效的 PE 文件 (缺少 PE 签名)")
		return false, nil, nil
	}
	return true, dosHeader, fileHeader
}

// 获取dos头信息
func dosheadInfo(dosHeader []byte) model.DosHeader {
	dosHeaderInfo := model.DosHeader{
		EMagic:    binary.LittleEndian.Uint16(dosHeader[:2]),
		ECblp:     binary.LittleEndian.Uint16(dosHeader[2:4]),
		ECp:       binary.LittleEndian.Uint16(dosHeader[4:6]),
		Ecrlc:     binary.LittleEndian.Uint16(dosHeader[6:8]),
		ECparhdr:  binary.LittleEndian.Uint16(dosHeader[8:10]),
		EMinalloc: binary.LittleEndian.Uint16(dosHeader[10:12]),
		EMaxalloc: binary.LittleEndian.Uint16(dosHeader[12:14]),
		ESS:       binary.LittleEndian.Uint16(dosHeader[14:16]),
		ESP:       binary.LittleEndian.Uint16(dosHeader[16:18]),
		ECsum:     binary.LittleEndian.Uint16(dosHeader[18:20]),
		EIp:       binary.LittleEndian.Uint16(dosHeader[20:22]),
		Ecs:       binary.LittleEndian.Uint16(dosHeader[22:24]),
		ELfarlc:   binary.LittleEndian.Uint16(dosHeader[24:26]),
		EOvno:     binary.LittleEndian.Uint16(dosHeader[26:28]),
		ERes: [4]uint16{
			binary.LittleEndian.Uint16(dosHeader[28:30]),
			binary.LittleEndian.Uint16(dosHeader[30:32]),
			binary.LittleEndian.Uint16(dosHeader[32:34]),
			binary.LittleEndian.Uint16(dosHeader[34:36]),
		},
		EOemid:   binary.LittleEndian.Uint16(dosHeader[36:38]),
		EOeminfo: binary.LittleEndian.Uint16(dosHeader[38:40]),
		ERes2: [10]uint16{
			binary.LittleEndian.Uint16(dosHeader[40:42]),
			binary.LittleEndian.Uint16(dosHeader[42:44]),
			binary.LittleEndian.Uint16(dosHeader[44:46]),
			binary.LittleEndian.Uint16(dosHeader[46:48]),
			binary.LittleEndian.Uint16(dosHeader[48:50]),
			binary.LittleEndian.Uint16(dosHeader[50:52]),
			binary.LittleEndian.Uint16(dosHeader[52:54]),
			binary.LittleEndian.Uint16(dosHeader[54:56]),
			binary.LittleEndian.Uint16(dosHeader[56:58]),
			binary.LittleEndian.Uint16(dosHeader[58:60]),
		},
		ELfanew: int32(binary.LittleEndian.Uint32(dosHeader[60:64])),
	}

	return dosHeaderInfo
}

// NTheadInfo 获取nt头信息
func NTheadInfo(file *os.File, dosInfo model.DosHeader, fileheader []byte) model.NTHeader {
	if len(fileheader) < 20 { // FileHeader 通常包20 字节
		fmt.Println("PE 文件头字节数据不足")
		return nil
	}

	// 读取 PE 文件头（FileHeader）信息
	var fileHeader model.FileHeader
	err := binary.Read(bytes.NewReader(fileheader[4:]), binary.LittleEndian, &fileHeader)
	if err != nil {
		log.Println("从字节数据中读取 PE 头失败:", err)
		return nil
	}

	optionalHeaderOffset := int64(dosInfo.ELfanew) + 24
	file.Seek(optionalHeaderOffset, 0)

	// 根据可选头大小读取数据
	optionalheader := make([]byte, fileHeader.SizeOfOptionalHeader)
	_, err = file.Read(optionalheader)

	// 读取 Magic 值
	magic := binary.LittleEndian.Uint16(optionalheader[:2])

	// 判断 Magic 值来确定 32 位或 64 位
	if magic == 0x10b { // 32 位可选头
		var optionalHeader model.OptionHeader32
		err = binary.Read(bytes.NewReader(optionalheader), binary.LittleEndian, &optionalHeader)
		if err != nil {
			log.Println("读取 32 位可选头失败:", err)
			return nil
		}

		// 返回 32 位 NT 头
		return &model.NTHeader32{
			Signature:      0x00004550, // "PE" 的 ASCII 值
			FileHeader:     fileHeader,
			OptionalHeader: optionalHeader,
		}

	} else if magic == 0x20b { // 64 位可选头
		var optionalHeader model.OptionHeader64
		err = binary.Read(bytes.NewReader(optionalheader), binary.LittleEndian, &optionalHeader)
		if err != nil {
			log.Println("读取 64 位可选头失败:", err)
			return nil
		}

		// 返回 64 位 NT 头
		return &model.NTHeader64{
			Signature:      0x00004550, // "PE" 的 ASCII 值
			FileHeader:     fileHeader,
			OptionalHeader: optionalHeader,
		}
	} else {
		log.Printf("未知的 Magic 值: 0x%X", magic)
		return nil
	}
}

// 通过映射表获取系统架构
func getMachineName(machine uint16) string {
	if name, exists := model.MachineMap[machine]; exists {
		return name
	}
	return "Unknown Machine"
}

func getSubsystemName(subsys uint16) string {
	if name, exists := model.SubsystemMap[int(int64(subsys))]; exists {
		return name
	}
	return "Unknown Machine"
}

// 获取节区表的信息
func getSections(file *os.File, fileHeader model.FileHeader, dosinfo model.DosHeader) ([]model.SectionHeader, int64, error) {
	// 计算节区表的起始位置
	sectionOffset := int64(dosinfo.ELfanew) + 24 + int64(fileHeader.SizeOfOptionalHeader)
	sectionTableEnd := sectionOffset + int64(fileHeader.NumberOfSections)*40

	// 可选头大小 + FileHeader的大小
	_, err := file.Seek(sectionOffset, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("无法跳转到节区表位置: %v", err)
	}

	// 读取节区头部信息
	sections := make([]model.SectionHeader, fileHeader.NumberOfSections)
	err = binary.Read(file, binary.LittleEndian, &sections)
	if err != nil {
		return nil, 0, fmt.Errorf("读取节区信息失败: %v", err)
	}
	remainingSpace := int64(sections[0].PointerToRawData) - sectionTableEnd
	return sections, remainingSpace, nil
}

// 32位导入表信息
func getImportTable32(optionheader model.OptionHeader32, sections []model.SectionHeader, file *os.File) model.ImportTable {
	if optionheader.DataDirectory[1].VirtualAddress == 0 || optionheader.DataDirectory[1].Size == 0 {
		return model.ImportTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".idata" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .idata 节区失败:", err)
				return model.ImportTable{}
			}
			importTable := model.ImportTable{}

			// 遍历导入描述符直到遇到终止符 (Characteristics == 0)
			for {
				var descriptor model.IMAGE_IMPORT_DESCRIPTOR
				err = binary.Read(file, binary.LittleEndian, &descriptor)
				if err != nil {
					log.Println("读取导入描述符失败:", err)
					return model.ImportTable{}
				}

				// 如果导入描述符的 Characteristics 字段为 0，表示导入表结束
				if descriptor.Characteristics == 0 {
					break
				}
				// 保存当前的文件偏移位置
				currentOffset, _ := file.Seek(0, io.SeekCurrent)

				// 提取 DLL 名称的 offset
				dllNameoffset := descriptor.Name - section.VirtualAddress + section.PointerToRawData

				// 根据 offset 查找 DLL 名称
				dllName := getDllName(file, dllNameoffset)
				importTable.DllName = append(importTable.DllName, dllName)
				file.Seek(currentOffset, io.SeekStart)
			}

			return importTable
		}
	}
	return model.ImportTable{}
}

// 64位导入表信息
func getImportTable64(optionheader model.OptionHeader64, sections []model.SectionHeader, file *os.File) model.ImportTable {
	if optionheader.DataDirectory[1].VirtualAddress == 0 || optionheader.DataDirectory[1].Size == 0 {
		return model.ImportTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".idata" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .idata 节区失败:", err)
				return model.ImportTable{}
			}
			importTable := model.ImportTable{}

			// 遍历导入描述符直到遇到终止符 (Characteristics == 0)
			for {
				var descriptor model.IMAGE_IMPORT_DESCRIPTOR
				err = binary.Read(file, binary.LittleEndian, &descriptor)
				if err != nil {
					log.Println("读取导入描述符失败:", err)
					return model.ImportTable{}
				}

				// 如果导入描述符的 Characteristics 字段为 0，表示导入表结束
				if descriptor.Characteristics == 0 {
					break
				}

				// 保存当前的文件偏移位置
				currentOffset, _ := file.Seek(0, io.SeekCurrent)

				// 提取 DLL 名称的 offset (根据 64 位 RVA 进行计算)
				dllNameOffset := uint64(descriptor.Name) - uint64(section.VirtualAddress) + uint64(section.PointerToRawData)
				// 根据 offset 查找 DLL 名称
				dllName := getDllName(file, uint32(dllNameOffset))
				importTable.DllName = append(importTable.DllName, dllName)

				// 跳回原来的文件偏移位置
				file.Seek(currentOffset, io.SeekStart)
			}

			return importTable
		}
	}
	return model.ImportTable{}
}

// 获取dll名
func getDllName(file *os.File, offset uint32) string {
	_, err := file.Seek(int64(offset), 0)
	if err != nil {
		log.Println("读取 DLL 名称失败:", err)
		return ""
	}

	// 读取字符串直到遇到 null 字符
	var nameBytes []byte
	for {
		var b byte
		err = binary.Read(file, binary.LittleEndian, &b)
		if err != nil {
			log.Println("读取字节失败:", err)
			return ""
		}
		if b == 0 {
			break
		}
		nameBytes = append(nameBytes, b)
	}

	// 将字节切片转换为字符串并返回
	return string(nameBytes)
}

// 32位导出表信息
func getExportTable32(optionheader model.OptionHeader32, sections []model.SectionHeader, file *os.File) model.ExportTable {
	if optionheader.DataDirectory[0].VirtualAddress == 0 || optionheader.DataDirectory[0].Size == 0 {
		return model.ExportTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".edata" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .edata 节区失败:", err)
				return model.ExportTable{}
			}
			exportTable := model.ExportTable{}

			// 遍历导入描述符直到遇到终止符 (Characteristics == 0)
			for {
				var descriptor model.IMAGE_EXPORT_DIRECTORY
				err = binary.Read(file, binary.LittleEndian, &descriptor)
				if err != nil {
					log.Println("读取导入描述符失败:", err)
					return model.ExportTable{}
				}

				// 提取 DLL 名称的 offset
				dllNameoffset := descriptor.Name - section.VirtualAddress + section.PointerToRawData
				dllName := getDllName(file, dllNameoffset)
				// 根据 offset 查找 DLL 名称
				exportTable.Name = dllName

				// 读取导出函数地址、名称和名称的索引
				// 获取函数的 RVA 地址、函数名称的 RVA、名称的索引
				functionAddresses := getFunctionAddresses(file, descriptor.AddressOfFunctions-section.VirtualAddress+section.PointerToRawData, descriptor.NumberOfFunctions)
				functionNames := getFunctionNames(file, descriptor.AddressOfNames-section.VirtualAddress+section.PointerToRawData, descriptor.NumberOfNames, section)

				// 将导出的函数信息添加到导出表
				for i := 0; i < int(descriptor.NumberOfNames); i++ {
					functionName := functionNames[i]
					functionAddr := functionAddresses[i]

					// 将函数名和地址封装到 ExportFunction 结构中
					exportTable.Func = append(exportTable.Func, model.ExportFunction{
						Name: functionName,
						Addr: functionAddr,
					})
				}
				return exportTable
			}
		}
	}
	return model.ExportTable{}
}

// 64位导出表信息
func getExportTable64(optionheader model.OptionHeader64, sections []model.SectionHeader, file *os.File) model.ExportTable {
	if optionheader.DataDirectory[0].VirtualAddress == 0 || optionheader.DataDirectory[0].Size == 0 {
		return model.ExportTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".edata" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .edata 节区失败:", err)
				return model.ExportTable{}
			}
			exportTable := model.ExportTable{}

			// 遍历导入描述符直到遇到终止符 (Characteristics == 0)
			for {
				var descriptor model.IMAGE_EXPORT_DIRECTORY
				err = binary.Read(file, binary.LittleEndian, &descriptor)
				if err != nil {
					log.Println("读取导入描述符失败:", err)
					return model.ExportTable{}
				}

				// 提取 DLL 名称的 offset
				dllNameoffset := descriptor.Name - section.VirtualAddress + section.PointerToRawData
				dllName := getDllName(file, dllNameoffset)
				// 根据 offset 查找 DLL 名称
				exportTable.Name = dllName

				// 读取导出函数地址、名称和名称的索引
				// 获取函数的 RVA 地址、函数名称的 RVA、名称的索引
				functionAddresses := getFunctionAddresses(file, descriptor.AddressOfFunctions-section.VirtualAddress+section.PointerToRawData, descriptor.NumberOfFunctions)
				functionNames := getFunctionNames(file, descriptor.AddressOfNames-section.VirtualAddress+section.PointerToRawData, descriptor.NumberOfNames, section)

				// 将导出的函数信息添加到导出表
				for i := 0; i < int(descriptor.NumberOfNames); i++ {
					functionName := functionNames[i]
					functionAddr := functionAddresses[i]

					// 将函数名和地址封装到 ExportFunction 结构中
					exportTable.Func = append(exportTable.Func, model.ExportFunction{
						Name: functionName,
						Addr: functionAddr,
					})
				}
				return exportTable
			}
		}
	}
	return model.ExportTable{}
}

// 获取导出方法的地址
func getFunctionAddresses(file *os.File, addressOfFunctions uint32, numberOfFunctions uint32) []uint32 {
	var functionAddresses []uint32
	_, err := file.Seek(int64(addressOfFunctions), 0)
	if err != nil {
		log.Println("读取函数地址失败:", err)
		return nil
	}

	for i := uint32(0); i < numberOfFunctions; i++ {
		var functionAddr uint32
		err = binary.Read(file, binary.LittleEndian, &functionAddr)
		if err != nil {
			log.Println("读取函数地址失败:", err)
			return nil
		}
		functionAddresses = append(functionAddresses, functionAddr)
	}

	return functionAddresses
}

// 获取导出函数名称
func getFunctionNames(file *os.File, addressOfNames uint32, numberOfNames uint32, section model.SectionHeader) []string {
	var functionNames []string
	_, err := file.Seek(int64(addressOfNames), 0)
	if err != nil {
		log.Println("读取函数名称失败:", err)
		return nil
	}
	var nameOffset uint32
	err = binary.Read(file, binary.LittleEndian, &nameOffset)
	for i := uint32(0); i < numberOfNames; i++ {
		if err != nil {
			log.Println("读取函数名称偏移失败:", err)
			return nil
		}
		name, currentOffset := getDllNameretadd(file, nameOffset-section.VirtualAddress+section.PointerToRawData) // 读取函数名称
		functionNames = append(functionNames, name)
		nameOffset = uint32(currentOffset) + section.VirtualAddress - section.PointerToRawData
	}

	return functionNames
}

// 获取dll名并返回当前地址
func getDllNameretadd(file *os.File, offset uint32) (string, int64) {
	_, err := file.Seek(int64(offset), 0)
	if err != nil {
		log.Println("读取 DLL 名称失败:", err)
		return "", 0
	}

	// 读取字符串直到遇到 null 字符
	var nameBytes []byte
	for {
		var b byte
		err = binary.Read(file, binary.LittleEndian, &b)
		if err != nil {
			log.Println("读取字节失败:", err)
			return "", 0
		}
		if b == 0 {
			break
		}
		nameBytes = append(nameBytes, b)
	}
	currentoffset, _ := file.Seek(0, io.SeekCurrent)
	// 将字节切片转换为字符串并返回
	return string(nameBytes), currentoffset
}

// 32位资源表信息
func getsrc32(optionheader model.OptionHeader32, sections []model.SectionHeader, file *os.File) model.ResourceTable {
	var resourceTable model.ResourceTable
	if optionheader.DataDirectory[2].VirtualAddress == 0 || optionheader.DataDirectory[2].Size == 0 {
		return model.ResourceTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".rsrc" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .rsrc 节区失败:", err)
				return model.ResourceTable{}
			}
			subaddr := section.VirtualAddress - section.PointerToRawData
			var dir model.IMAGE_RESOURCE_DIRECTORY
			err = binary.Read(file, binary.LittleEndian, &dir)
			if err != nil {
				return model.ResourceTable{}
			}
			srcnumber := dir.NumberOfNamedEntries + dir.NumberOfIdEntries
			resourceTable.Entry = first(srcnumber, file, int64(section.PointerToRawData), subaddr)
		}
	}
	return resourceTable
}

// 64位资源表信息
func getsrc64(optionheader model.OptionHeader64, sections []model.SectionHeader, file *os.File) model.ResourceTable {
	var resourceTable model.ResourceTable
	if optionheader.DataDirectory[2].VirtualAddress == 0 || optionheader.DataDirectory[2].Size == 0 {
		return model.ResourceTable{}
	}
	for _, section := range sections {
		sectionName := string(bytes.TrimRight(section.Name[:], "\x00"))
		if sectionName == ".rsrc" {
			_, err := file.Seek(int64(section.PointerToRawData), 0)
			if err != nil {
				log.Println("读取 .rsrc 节区失败:", err)
				return model.ResourceTable{}
			}
			subaddr := section.VirtualAddress - section.PointerToRawData
			var dir model.IMAGE_RESOURCE_DIRECTORY
			err = binary.Read(file, binary.LittleEndian, &dir)
			if err != nil {
				return model.ResourceTable{}
			}
			srcnumber := dir.NumberOfNamedEntries + dir.NumberOfIdEntries
			resourceTable.Entry = first(srcnumber, file, int64(section.PointerToRawData), subaddr)
		}
	}
	return resourceTable
}

// 第一层解析
func first(srcNumber uint16, file *os.File, base int64, subaddr uint32) model.Entry {
	var retentry model.Entry
	// 循环读取资源目录项
	for i := uint16(0); i < srcNumber; i++ {
		// 读取一个资源目录项
		var entry model.IMAGE_RESOURCE_DIRECTORY_ENTRY
		err := binary.Read(file, binary.LittleEndian, &entry)
		if err != nil {
			log.Println("读取资源目录项失败:", err)
			return retentry
		}
		switch entry.Name {
		case 0x01: // 光标 (Cursor)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Cursor = append(retentry.Cursor, t)
			}

		case 0x02: // 位图 (Bitmap)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Bitmap = append(retentry.Bitmap, t)
			}

		case 0x03: // 图标 (Icon)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Icon = append(retentry.Icon, t)
			}

		case 0x04: // 菜单 (Menu)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Menu = append(retentry.Menu, t)
			}

		case 0x05: // 对话框 (Dialog)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Dialog = append(retentry.Dialog, t)
			}

		case 0x06: // 字符串 (String)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.String = append(retentry.String, t)
			}

		case 0x07: // 字体目录 (Font Directory)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.FontDirectory = append(retentry.FontDirectory, t)
			}

		case 0x08: // 字体 (Font)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Font = append(retentry.Font, t)
			}

		case 0x09: // 加速键 (Accelerators)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Accelerators = append(retentry.Accelerators, t)
			}

		case 0x0A: // 未格式化资源 (Unformatted)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.Unformatted = append(retentry.Unformatted, t)
			}

		case 0x0B: // 消息表 (MessageTable)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.MessageTable = append(retentry.MessageTable, t)
			}

		case 0x0C: // 组光标 (Group Cursor)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.GroupCursor = append(retentry.GroupCursor, t)
			}

		case 0x0E: // 图标组 (Group Icon)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.GroupIcon = append(retentry.GroupIcon, t)
			}

		case 0x10: // 版本信息 (Version Information)
			for _, t := range second(entry, base, file, subaddr) {
				retentry.VersionInfo = append(retentry.VersionInfo, t)
			}
		}
	}
	return retentry
}

// 第二层解析
func second(entry model.IMAGE_RESOURCE_DIRECTORY_ENTRY, base int64, file *os.File, subaddr uint32) []model.Tmp {
	var tmp []model.Tmp
	if checkhighbit(entry.OffsetToData) {
		remainingBits := entry.OffsetToData & 0x7FFFFFFF // 屏蔽最高位
		actualOffset := int64(remainingBits) + base
		file.Seek(actualOffset, 0)
		var dir model.IMAGE_RESOURCE_DIRECTORY
		err := binary.Read(file, binary.LittleEndian, &dir)
		if err != nil {
			log.Println("文件读取失败")
			return nil
		}
		srcnum := dir.NumberOfNamedEntries + dir.NumberOfIdEntries
		for i := uint16(0); i < srcnum; i++ {
			var t model.Tmp
			var secentry model.IMAGE_RESOURCE_DIRECTORY_ENTRY
			err = binary.Read(file, binary.LittleEndian, &secentry)
			if err != nil {
				log.Println("读取资源目录项失败:", err)
				return nil
			}
			if checkhighbit(secentry.Name) {
				stringnameaddr := entry.Name & 0x7FFFFFFF
				file.Seek(int64(stringnameaddr)+base, 0)
				name, err := readUnicodeString(file, int64(stringnameaddr))
				if err != nil {
					log.Println("读取字符串失败:", err)
					return nil
				}
				t.Name = name
			} else {
				t.Name = strconv.Itoa(int(secentry.Name))
			}
			t.Fileaddr, t.Size = third(secentry, file, base, subaddr)
			tmp = append(tmp, t)
		}
	} else {
		var t model.Tmp
		structOffset := int64(entry.OffsetToData) + base
		// 跳转到结构所在的位置
		_, err := file.Seek(structOffset, 0)
		if err != nil {
			log.Println("无法跳转到结构偏移地址:", err)
			return nil
		}

		// 读取 IMAGE_RESOURCE_DATA_ENTRY 结构
		var dataEntry model.IMAGE_RESOURCE_DATA_ENTRY
		err = binary.Read(file, binary.LittleEndian, &dataEntry)
		if err != nil {
			log.Println("无法读取 IMAGE_RESOURCE_DATA_ENTRY 结构:", err)
			return nil
		}

		// 计算资源数据的实际地址 (例如在内存或文件中的偏移)
		t.Fileaddr = int64(dataEntry.OffsetToData - subaddr)
		t.Size = dataEntry.Size
		tmp = append(tmp, t)
	}
	for i, t := range tmp {
		// 创建一个缓冲区用于存储字节数据
		var buf bytes.Buffer

		// 使用 binary.Write 将 Fileaddr 和 Size 写入字节流
		binary.Write(&buf, binary.LittleEndian, t.Fileaddr) // 写入 Fileaddr
		binary.Write(&buf, binary.LittleEndian, t.Size)     // 写入 Size

		// 将字节流赋值给 Content 字段
		tmp[i].Content = buf.Bytes()
	}
	return tmp
}

// 第三层解析
func third(entry model.IMAGE_RESOURCE_DIRECTORY_ENTRY, file *os.File, base int64, subaddr uint32) (int64, uint32) {
	if checkhighbit(entry.OffsetToData) {
		remainingBits := entry.OffsetToData & 0x7FFFFFFF
		actualOffset := int64(remainingBits) + base
		file.Seek(actualOffset, 0)
		var dir model.IMAGE_RESOURCE_DIRECTORY
		err := binary.Read(file, binary.LittleEndian, &dir)
		if err != nil {
			log.Println("无法跳转文件地址", err)
			return 0, 0
		}
		var thientry model.IMAGE_RESOURCE_DIRECTORY_ENTRY
		err = binary.Read(file, binary.LittleEndian, &thientry)
		if err != nil {
			log.Println("读取资源目录项失败:", err)
			return 0, 0
		}
		return end(thientry, file, base, subaddr)
	} else {
		structOffset := int64(entry.OffsetToData) + base

		// 跳转到结构所在的位置
		_, err := file.Seek(structOffset, 0)
		if err != nil {
			log.Println("无法跳转到结构偏移地址:", err)
			return 0, 0
		}

		// 读取 IMAGE_RESOURCE_DATA_ENTRY 结构
		var dataEntry model.IMAGE_RESOURCE_DATA_ENTRY
		err = binary.Read(file, binary.LittleEndian, &dataEntry)
		if err != nil {
			log.Println("无法读取 IMAGE_RESOURCE_DATA_ENTRY 结构:", err)
			return 0, 0
		}

		return int64(dataEntry.OffsetToData - subaddr), dataEntry.Size
	}
	return 0, 0
}

// 最终数据获取
func end(entry model.IMAGE_RESOURCE_DIRECTORY_ENTRY, file *os.File, base int64, subaddr uint32) (int64, uint32) {
	actuaddr := int64(entry.OffsetToData) + base
	file.Seek(actuaddr, 0)
	var src model.IMAGE_RESOURCE_DATA_ENTRY
	err := binary.Read(file, binary.LittleEndian, &src)
	if err != nil {
		return 0, 0
	}
	return int64(src.OffsetToData) - int64(subaddr), src.Size
}

// 检查最高位地址
func checkhighbit(Data uint32) bool {
	highestByte := uint8(Data >> 24)
	// 转成二进制，检查最高位是否为 1
	highestBit := (highestByte >> 7) & 1 // 获取最高位
	if highestBit == 1 {
		return true
	} else {
		return false
	}
}

// 读取字符串名字
func readUnicodeString(file *os.File, offset int64) (string, error) {
	// 跳转到指定的偏移地址
	_, err := file.Seek(offset, 0)
	if err != nil {
		return "", err
	}

	// 读取 Length (WORD 类型)
	var length uint16
	err = binary.Read(file, binary.LittleEndian, &length)
	if err != nil {
		return "", err
	}

	// 读取 NameString (UNICODE，每字符 2 字节)
	nameString := make([]uint16, length)
	err = binary.Read(file, binary.LittleEndian, &nameString)
	if err != nil {
		return "", err
	}

	// 将 UNICODE 字符串转换为 UTF-8
	var buffer bytes.Buffer
	for _, wchar := range nameString {
		buffer.WriteRune(rune(wchar)) // 转换为 Go 的 Unicode 字符
	}

	return buffer.String(), nil
}
func ProcessFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	// 读取文件内容
	data, err := io.ReadAll(file)
	if err != nil {
		return nil
	}

	// 转换为每行格式化的 hex 字符串
	lines := formatHexLines(data)
	return lines
}

// formatHexLines 格式化二进制数据为每行的16进制和ASCII字符串
func formatHexLines(data []byte) []string {
	var lines []string
	const bytesPerLine = 16

	for offset := 0; offset < len(data); offset += bytesPerLine {
		// 写入偏移量（8位十六进制）
		line := fmt.Sprintf("%08X  ", offset)

		// 初始化 16进制部分和 ASCII 部分
		hexPart := ""
		asciiPart := ""

		for i := 0; i < bytesPerLine; i++ {
			if offset+i < len(data) {
				hexPart += fmt.Sprintf("%02X ", data[offset+i])
				// 每8个字节添加一个额外的空格以增加可读性
				if (i+1)%8 == 0 {
					hexPart += " "
				}
				b := data[offset+i]
				if b >= 32 && b <= 126 { // 判断是否为可打印字符
					asciiPart += string(b)
				} else {
					asciiPart += "."
				}
			} else {
				hexPart += "   " // 填充空格以保持对齐
				asciiPart += " "
			}
		}

		// 确保每行的 hexPart 长度一致（填充）
		hexPart = fmt.Sprintf("%-49s", hexPart)

		// 组合完整的一行
		line += hexPart + " | " + asciiPart

		// 添加到行切片中
		lines = append(lines, line)
	}

	return lines
}
