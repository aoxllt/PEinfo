package gui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"io/ioutil"
	"log"
	"regexp"
	"rev/detect"
	"rev/model"
	"strconv"
	"strings"
)

const (
	width  = 800
	height = 350
)

type HexEditor struct {
	lines []string // 每行的格式化16进制和ASCII数据
	list  *widget.List
}

var formattedHex []string
var importlistlen int = 0
var exportlistlen int = 0
var importdata []string
var treeData model.ExportTable
var resdata model.ResourceTable
var infodata model.Info
var optiondata [][]string
var sectionhead = []model.SectionHeader{}
var datasetcion = [16]model.DataDirectory{}
var process = model.Process{}
var iconData, _ = ioutil.ReadFile("./favoicon.jpg")
var icon = fyne.NewStaticResource("icon.jpg", iconData)
var createTable = func(data []model.Tmp) fyne.CanvasObject {
	var rows []fyne.CanvasObject
	for _, r := range data {
		row := container.NewHBox(
			widget.NewLabel("  "),
			widget.NewLabel(r.Name),
			widget.NewLabel(fmt.Sprintf("0x%X", r.Fileaddr)),
			widget.NewLabel(fmt.Sprintf("0x%X", r.Size)),
		)
		rows = append(rows, row)
	}
	return container.NewVBox(rows...)
}

func init() {

}

func Creategui() {

	a := app.New()
	a.Settings().SetTheme(theme.LightTheme())
	w := a.NewWindow("pe信息检测")
	w.Resize(fyne.NewSize(width, height))
	w.SetFixedSize(true)
	process.Processname = detect.ProcessName()
	process.Pid = detect.ProcessId()
	fileInput := widget.NewEntry()
	fileInput.SetPlaceHolder("选择检测的文件")
	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		if len(uris) == 0 {
			log.Println("未检测到任何文件拖放")
			return
		}
		uri := uris[0]
		path := uri.Path()
		fileInput.SetText(path)
		model.C <- path
	})
	uploadBtn := widget.NewButton("选择文件", func() {
		filter := storage.NewExtensionFileFilter([]string{".exe", ".dll"})
		fileOpen := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil {
				log.Fatalln("文件打开失败", err)
				return
			}
			if uc != nil {
				fileInput.SetText(uc.URI().String())
				model.C <- uc.URI().String()
				uc.Close()
			}
		}, w)
		fileOpen.SetFilter(filter)
		fileOpen.Show()
	})
	Space := container.New(layout.NewGridWrapLayout(fyne.NewSize(100, 20)))
	c1 := container.New(
		layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.01, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.69, 38)), fileInput),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 35)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.2, 35)), uploadBtn),
	)

	// 文件类型、文件大小、基址 输入框
	fileTypeLabel := widget.NewLabel("文件类型:")
	fileSizeLabel := widget.NewLabel("文件大小:")
	baseLabel := widget.NewLabel("基址:")
	entrypointLable := widget.NewLabel("入口点(VA/RVA):")
	fileTypeEntry := widget.NewEntry()
	fileSizeEntry := widget.NewEntry()
	baseEntry := widget.NewEntry()
	entrypointEntry := widget.NewEntry()
	connecterLabel := widget.NewLabel("连接器版本:")
	connecterEntry := widget.NewEntry()
	connecterEntry.Resize(fyne.NewSize(width, 25))
	MachineinfoLabel := widget.NewLabel("架构:")
	MachineinfoEntry := widget.NewEntry()
	CreateTimeLabel := widget.NewLabel("创建时间:")
	CreateTimeEntry := widget.NewEntry()
	OsVersionLabel := widget.NewLabel("OS版本:")
	OsVersionEntry := widget.NewEntry()
	ImageVersionLabel := widget.NewLabel("Image版本:")
	ImageVersionEntry := widget.NewEntry()
	SubsystemLabel := widget.NewLabel("子系统:")
	SubsystemEntry := widget.NewEntry()
	SFAlignmentLabel := widget.NewLabel("Section/FileAlignment:")
	SFAlignmentEntry := widget.NewEntry()
	infobtn := widget.NewButton("文件信息", func() {
		w1 := a.NewWindow("文件信息")
		w1.Resize(fyne.NewSize(width, height))
		w1.SetIcon(icon)

		dosdata := [][]string{
			{"魔数(EMagic)", fmt.Sprintf("0x%04x", infodata.DosHeader.EMagic)},         // EMagic
			{"重定位段大小(ECblp)", fmt.Sprintf("0x%04x", infodata.DosHeader.ECblp)},       // ECblp
			{"重定位项数(ECp)", fmt.Sprintf("0x%04x", infodata.DosHeader.ECp)},            // ECp
			{"重定位项(Ecrlc)", fmt.Sprintf("0x%04x", infodata.DosHeader.Ecrlc)},         // Ecrlc
			{"头部段偏移(ECparhdr)", fmt.Sprintf("0x%04x", infodata.DosHeader.ECparhdr)},  // ECparhdr
			{"最小内存(EMinalloc)", fmt.Sprintf("0x%04x", infodata.DosHeader.EMinalloc)}, // EMinalloc
			{"最大内存(EMaxalloc)", fmt.Sprintf("0x%04x", infodata.DosHeader.EMaxalloc)}, // EMaxalloc
			{"堆栈段指针(ESS)", fmt.Sprintf("0x%04x", infodata.DosHeader.ESS)},            // ESS
			{"堆栈指针(ESP)", fmt.Sprintf("0x%04x", infodata.DosHeader.ESP)},             // ESP
			{"校验和(ECsum)", fmt.Sprintf("0x%04x", infodata.DosHeader.ECsum)},          // ECsum
			{"IP寄存器(EIp)", fmt.Sprintf("0x%04x", infodata.DosHeader.EIp)},            // EIp
			{"代码段寄存器(Ecs)", fmt.Sprintf("0x%04x", infodata.DosHeader.Ecs)},           // Ecs
			{"文件头偏移(ELfarlc)", fmt.Sprintf("0x%04x", infodata.DosHeader.ELfarlc)},    // ELfarlc
			{"版本号(EOvno)", fmt.Sprintf("0x%04x", infodata.DosHeader.EOvno)},          // EOvno
			{"OEM标识符(EOemid)", fmt.Sprintf("0x%04x", infodata.DosHeader.EOemid)},     // EOemid
			{"OEM信息(EOeminfo)", fmt.Sprintf("0x%04x", infodata.DosHeader.EOeminfo)},  // EOeminfo
			{"新PE头偏移(ELfanew)", fmt.Sprintf("0x%04x", infodata.DosHeader.ELfanew)},   // ELfanew
		}

		filedata := [][]string{
			{"机器类型(Machine)", fmt.Sprintf("0x%04x", infodata.NTHeader.GetFileHeader().Machine)},                            // Machine
			{"节区数量(NumberOfSections)", fmt.Sprintf("0x%04x", infodata.NTHeader.GetFileHeader().NumberOfSections)},          // NumberOfSections
			{"时间戳(TimeDateStamp)", fmt.Sprintf("0x%08x", infodata.NTHeader.GetFileHeader().TimeDateStamp)},                 // TimeDateStamp
			{"符号表指针(PointerToSymbolTable)", fmt.Sprintf("0x%08x", infodata.NTHeader.GetFileHeader().PointerToSymbolTable)}, // PointerToSymbolTable
			{"符号表数量(NumberOfSymbols)", fmt.Sprintf("0x%08x", infodata.NTHeader.GetFileHeader().NumberOfSymbols)},           // NumberOfSymbols
			{"可选头大小(SizeOfOptionalHeader)", fmt.Sprintf("0x%04x", infodata.NTHeader.GetFileHeader().SizeOfOptionalHeader)}, // SizeOfOptionalHeader
			{"文件特征(Characteristics)", fmt.Sprintf("0x%04x", infodata.NTHeader.GetFileHeader().Characteristics)},            // Characteristics
		}

		headers := []string{
			"索引(Index)", "名称(Name)", "虚拟大小(VirtualSize)", "虚拟地址(VirtualAddress)", "原始数据大小(Size of Raw Data)", // "Index", "Name", "VirtualSize", "VirtualAddress", "Size of Raw Data"
			"原始数据指针(Pointer to Raw Data)", "特征(Characteristics)", // "Pointer to Raw Data", "Characteristics"
		}

		dataheaders := []string{
			"索引(Index)", "名称(Name)", "虚拟地址(Virtual Address)", "虚拟大小(Virtual Size)", // "Index", "Name", "Virtual Address", "Virtual Size"
		}

		name := []string{
			"导出表(EXPORT)", "导入表(IMPORT)", "资源表(RESOURCE)", "异常表(EXCEPTION)", "安全表(SECURITY)", "基本重定位表(BASERELOC)", // "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC"
			"调试信息(DEBUG)", "架构表(ARCHITECTURE)", "全局指针表(GLOBALPTR)", "线程局部存储(TLS)", "加载配置(LOAD_CONFIG)", // "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG"
			"边界导入表(BOUND_IMPORT)", "IAT表(IAT)", "延迟导入表(DELAY_IMPORT)", "COM描述符表(COM_DESCRIPTOR)", "保留表(RESERVED)", // "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
		}

		drows := [][]string{dataheaders}

		// Ensure iteration does not exceed the length of either slice
		for i, d := range datasetcion {
			drows = append(drows, []string{
				fmt.Sprintf("%d", i),
				name[i],
				fmt.Sprintf("0x%08X", d.VirtualAddress),
				fmt.Sprintf("0x%08X", d.Size),
			})
		}

		datac := container.NewGridWithColumns(len(dataheaders))
		for _, header := range dataheaders {
			datac.Add(widget.NewLabel(header))
		}

		// Add table rows to the grid
		for _, row := range drows[1:] { // Skip headers, already added
			for _, cell := range row {
				datac.Add(widget.NewLabel(cell))
			}
		}
		srows := [][]string{headers}
		for i, s := range sectionhead {
			srows = append(srows, []string{
				fmt.Sprintf("%d", i),
				string(s.Name[:]),
				fmt.Sprintf("0x%08X", s.VirtualSize),
				fmt.Sprintf("0x%08X", s.VirtualAddress),
				fmt.Sprintf("0x%08X", s.SizeOfRawData),
				fmt.Sprintf("0x%08X", s.PointerToRawData),
				fmt.Sprintf("0x%08X", s.Characteristics),
			})
		}

		grid := container.NewGridWithColumns(len(headers))
		for _, header := range headers {
			grid.Add(widget.NewLabel(header))
		}

		for _, row := range srows[1:] {
			for _, cell := range row {
				grid.Add(widget.NewLabel(cell))
			}
		}

		dosc := container.New(layout.NewGridWrapLayout(fyne.Size{
			Width:  width,
			Height: height,
		}), widget.NewTable(
			func() (int, int) {
				return len(dosdata), len(dosdata[0]) // 返回表格的行数和列数
			},
			func() fyne.CanvasObject {
				return widget.NewLabel("tableaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 每个单元格是一个 Label
			},
			func(i widget.TableCellID, o fyne.CanvasObject) {
				label := o.(*widget.Label)
				label.SetText(dosdata[i.Row][i.Col]) // 填充每个单元格的文本
			},
		))
		filec := container.New(layout.NewGridWrapLayout(fyne.Size{
			Width:  width,
			Height: height,
		}), widget.NewTable(
			func() (int, int) {
				return len(filedata), len(filedata[0]) // 返回表格的行数和列数
			},
			func() fyne.CanvasObject {
				return widget.NewLabel("tableaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 每个单元格是一个 Label
			},
			func(i widget.TableCellID, o fyne.CanvasObject) {
				label := o.(*widget.Label)
				label.SetText(filedata[i.Row][i.Col]) // 填充每个单元格的文本
			},
		))
		optionc := container.New(layout.NewGridWrapLayout(fyne.Size{
			Width:  width,
			Height: height,
		}), widget.NewTable(
			func() (int, int) {
				return len(optiondata), len(optiondata[0]) // 返回表格的行数和列数
			},
			func() fyne.CanvasObject {
				return widget.NewLabel("tableaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 每个单元格是一个 Label
			},
			func(i widget.TableCellID, o fyne.CanvasObject) {
				label := o.(*widget.Label)
				label.SetText(optiondata[i.Row][i.Col]) // 填充每个单元格的文本
			},
		))

		rightc := container.NewVBox(dosc)
		Dosheader := widget.NewButton("Dos头信息", func() {
			rightc.Objects = []fyne.CanvasObject{dosc}
			rightc.Refresh()
		})
		Fileheader := widget.NewButton("文件头信息", func() {
			rightc.Objects = []fyne.CanvasObject{filec}
			rightc.Refresh()
		})
		Optionheader := widget.NewButton("可选头信息", func() {
			rightc.Objects = []fyne.CanvasObject{optionc}
			rightc.Refresh()
		})
		DataDir := widget.NewButton("数据目录信息", func() {
			rightc.Objects = []fyne.CanvasObject{datac}
			rightc.Refresh()
		})
		sectionheader := widget.NewButton("节区信息", func() {
			rightc.Objects = []fyne.CanvasObject{grid}
			rightc.Refresh()
		})
		leftc := container.NewVBox(Dosheader, Fileheader, Optionheader, DataDir, sectionheader)
		split := container.NewHSplit(leftc, rightc)
		split.SetOffset(3 / 5)
		w1.SetContent(split)
		w1.Show()

	})

	importbtn := widget.NewButton("导入表", func() {
		w2 := a.NewWindow("导入表")
		w2.Resize(fyne.NewSize(width, height))
		w2.SetIcon(icon)
		var rows []fyne.CanvasObject
		for _, item := range importdata {
			// 每个数据项创建一行
			row := container.NewGridWithColumns(1, widget.NewLabel(item))
			rows = append(rows, row) // 将行添加到行容器中
		}

		// 将所有的行容器放入一个垂直容器中
		table := container.NewVBox(rows...)

		w2.SetContent(container.NewVBox(
			widget.NewLabel("导入表列表:"),
			table,
		))

		w2.Show()
	})
	exportbtn := widget.NewButton("导出表", func() {
		w3 := a.NewWindow("导出表")
		w3.Resize(fyne.NewSize(width, height))
		w3.SetIcon(icon)
		var rows []fyne.CanvasObject
		for _, t := range treeData.Func {
			row := container.NewHBox(
				widget.NewLabel("  "),
				widget.NewLabel(t.Name),                      // 方法名
				widget.NewLabel(fmt.Sprintf("0x%X", t.Addr)), // 地址
			)
			rows = append(rows, row)
		}
		table := container.NewVBox(rows...)
		w3.SetContent(container.NewVBox(
			widget.NewLabel("导出表列表:"),
			widget.NewLabel(treeData.Name),
			table,
		))
		w3.Show()
	})
	resbtn := widget.NewButton("资源表", func() {
		w4 := a.NewWindow("资源表")
		w4.Resize(fyne.NewSize(width, height))
		w4.SetIcon(icon)
		Icontable := createTable(resdata.Entry.Icon)
		Cursortable := createTable(resdata.Entry.Cursor)
		BitmapTable := createTable(resdata.Entry.Bitmap)
		Menutable := createTable(resdata.Entry.Menu)
		Dialogtable := createTable(resdata.Entry.Dialog)
		Stringtable := createTable(resdata.Entry.String)
		FontDirectorytable := createTable(resdata.Entry.FontDirectory)
		Fonttable := createTable(resdata.Entry.Font)
		Acceleratorstable := createTable(resdata.Entry.Accelerators)
		Unformattedtable := createTable(resdata.Entry.Unformatted)
		Messagetable := createTable(resdata.Entry.MessageTable)
		GroupCursortable := createTable(resdata.Entry.GroupCursor)
		GroupIcontable := createTable(resdata.Entry.GroupIcon)
		VersionInfotable := createTable(resdata.Entry.VersionInfo)
		w4.SetContent(container.NewVBox(
			widget.NewLabel("资源表列表:"),
			widget.NewLabel("Icon:"),
			Icontable,
			widget.NewLabel("Cursor:"),
			Cursortable,
			widget.NewLabel("Bitmap:"),
			BitmapTable,
			widget.NewLabel("Menu:"),
			Menutable,
			widget.NewLabel("Dialog:"),
			Dialogtable,
			widget.NewLabel("String:"),
			Stringtable,
			widget.NewLabel("Font Directory:"),
			FontDirectorytable,
			widget.NewLabel("Font:"),
			Fonttable,
			widget.NewLabel("Accelerators:"),
			Acceleratorstable,
			widget.NewLabel("Unformatted:"),
			Unformattedtable,
			widget.NewLabel("Message Table:"),
			Messagetable,
			widget.NewLabel("Group Cursor:"),
			GroupCursortable,
			widget.NewLabel("Group Icon:"),
			GroupIcontable,
			widget.NewLabel("Version Info:"),
			VersionInfotable,
		))
		w4.Show()
	})
	injecttbtn := widget.NewButton("DLL注入", func() {
		w5 := a.NewWindow("DLL注入")
		w5.Resize(fyne.NewSize(width, height))
		w5.SetIcon(icon)

		// 表头
		tablehead := []string{
			"选择", "序号", "进程名", "进程ID",
		}

		// 创建搜索框
		searchEntry := widget.NewEntry()
		searchEntry.SetPlaceHolder("搜索进程...")

		// 创建一个容器来保存搜索框
		searchContainer := container.NewHBox(widget.NewLabel("搜索："), searchEntry)

		// 用来存储进程的所有行数据
		var processRows []fyne.CanvasObject

		// 表格数据
		trows := [][]string{tablehead}
		for i := 0; i < len(process.Pid) && i < len(process.Processname); i++ {
			trows = append(trows, []string{
				fmt.Sprintf("%d", i),
				process.Processname[i],
				fmt.Sprintf("%d", process.Pid[i]),
			})
		}

		// 创建显示进程的行数据
		updateRows := func(query string) {
			processc := container.NewVBox() // 清空容器

			// 表头
			headerRow := container.NewGridWithColumns(len(tablehead))
			for _, header := range tablehead {
				headerRow.Add(widget.NewLabel(header))
			}
			processc.Add(headerRow)

			// 添加单选框（Radio Group）
			var radioItems []string
			for i, row := range trows[1:] {
				processName := row[1]
				if query != "" && !containsIgnoreCase(processName, query) {
					continue // 跳过不匹配的行
				}
				radioItems = append(radioItems, fmt.Sprintf("\t\t\t\t%d\t\t\t\t\t%s\t\t\t%d", i, processName, process.Pid[i])) // 将进程名作为单选项

			}

			// 创建一个RadioGroup，只允许选择一个
			radio := widget.NewRadioGroup(radioItems, func(selected string) {
				w5.Hide()
				re := regexp.MustCompile(`\d+$`)
				pid, _ := strconv.ParseUint(re.FindString(selected), 10, 32)
				w6 := a.NewWindow("DLL注入")
				w6.Resize(fyne.NewSize(width, height))
				w6.SetIcon(icon)
				fileInput6 := widget.NewEntry()
				fileInput6.SetPlaceHolder("选择检测的文件")

				// 监听文件拖放事件
				w6.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
					if len(uris) == 0 {
						log.Println("未检测到任何文件拖放")
						return
					}
					uri := uris[0]
					path := uri.Path()

					// 检查文件扩展名是否为 .dll
					if !isDLLFile(path) {
						dialog.NewConfirm("错误", "只允许拖入 DLL 文件", func(confirm bool) {
							if confirm {
								// 用户点击了确认按钮
								log.Println("用户确认了错误消息")
							} else {
								// 用户点击了取消按钮
								log.Println("用户取消了错误消息")
							}
						}, w6).Show()
					}

					model.P <- model.Pr{Pid: uint32(pid), Path: path}
					fileInput6.SetText(path)
				})

				// 文件选择按钮
				uploadBtn6 := widget.NewButton("选择文件", func() {
					filter := storage.NewExtensionFileFilter([]string{".dll"})
					fileOpen := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
						if err != nil {
							log.Fatalln("文件打开失败", err)
							return
						}
						if uc != nil {
							fileInput6.SetText(uc.URI().String())
							model.P <- model.Pr{Pid: uint32(pid), Path: uc.URI().String()}
							uc.Close()
						}
					}, w6)
					fileOpen.SetFilter(filter)
					fileOpen.Show()
				})
				Space6 := container.New(layout.NewGridWrapLayout(fyne.NewSize(100, 20)))

				// 设置窗口内容
				w6.SetContent(container.New(
					layout.NewHBoxLayout(),
					container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.01, 38)), Space6),
					container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.69, 38)), fileInput6),
					container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 35)), Space6),
					container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.2, 35)), uploadBtn6),
				))
				w6.Show()

			})

			// 将RadioGroup添加到容器
			processc.Add(radio)

			// 更新显示的进程行
			if len(processRows) > 0 {
				for _, row := range processRows {
					processc.Remove(row)
				}
			}

			processRows = append(processRows, processc.Objects...)
			w5.SetContent(container.NewVBox(searchContainer, container.New(layout.NewGridWrapLayout(fyne.Size{
				Width:  width,
				Height: height,
			}), container.NewScroll(processc)))) // 包装在Scroll容器中
		}

		// 搜索功能：监听文本框变化
		searchEntry.OnChanged = func(s string) {
			updateRows(s)
		}

		// 初始化时显示所有进程
		updateRows("")

		w5.Show()
	})
	revbtn := widget.NewButton("16进制", func() {
		openHexViewerWindow(a, formattedHex)
	})

	c2 := container.New(layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.005, 30)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 30)), fileTypeLabel), // 缩小一半
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 30)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 30)), fileSizeLabel), // 缩小一半
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.2, 30)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 30)), baseLabel),       // 扩大一倍
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.25, 30)), entrypointLable), // 扩大一倍
	)
	// 创建水平布局并将这些带有间距的输入框放在一起
	c3 := container.New(
		layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.01, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), fileTypeEntry), // 缩小一半
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), fileSizeEntry), // 缩小一半
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.2, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), baseEntry),       // 扩大一倍
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.25, 38)), entrypointEntry), // 扩大一倍
	)
	c4 := container.New(
		layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.11, 38)), connecterLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.065, 38)), connecterEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.05, 38)), MachineinfoLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.165, 38)), MachineinfoEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.09, 38)), CreateTimeLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.22, 38)), CreateTimeEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.08, 38)), OsVersionLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.055, 38)), OsVersionEntry),
	)
	c5 := container.New(layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.11, 38)), ImageVersionLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.055, 38)), ImageVersionEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.07, 38)), SubsystemLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), SubsystemEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.2, 38)), SFAlignmentLabel),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), SFAlignmentEntry),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), infobtn),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), injecttbtn),
	)
	c6 := container.New(layout.NewHBoxLayout(),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), importbtn),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), exportbtn),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), resbtn),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.15, 38)), Space),
		container.New(layout.NewGridWrapLayout(fyne.NewSize(width*0.1, 38)), revbtn),
	)

	// 启动一个 goroutine 来处理接收扫描结果
	go func() {
		for {
			select {
			case result := <-model.ResultChan:
				// 收到检测结果后，更新 GUI
				formattedHex = result.F
				infodata = result
				fileTypeEntry.SetText(result.OtherInfo.Bit)
				fileSizeEntry.SetText(result.OtherInfo.FileSize)
				CreateTimeEntry.SetText(result.OtherInfo.CreateTime.Format("2006-01-02 15:04:05"))
				connecterEntry.SetText(result.OtherInfo.ConnectorVersion)
				MachineinfoEntry.SetText(result.OtherInfo.Machineinfo)
				OsVersionEntry.SetText(result.OtherInfo.OsVersion)
				ImageVersionEntry.SetText(result.OtherInfo.ImageVersion)
				SubsystemEntry.SetText(result.OtherInfo.Subsystem)
				importlistlen = len(result.ImportTable.DllName)
				importdata = result.ImportTable.DllName
				treeData = result.ExportTable
				resdata = result.ResourceTable
				sectionhead = result.SectionHeader
				switch h := result.NTHeader.GetOptionalHeader().(type) {
				case model.OptionHeader32:
					baseEntry.SetText(fmt.Sprintf("0x%X", h.ImageBase))
					entrypointEntry.SetText(fmt.Sprintf("0x%X/0x%X", h.ImageBase+h.AddressOfEntryPoint, h.AddressOfEntryPoint))
					SFAlignmentEntry.SetText(fmt.Sprintf("0x%X/0x%X", h.SectionAlignment, h.FileAlignment))
					datasetcion = h.DataDirectory
					optiondata = [][]string{
						{"魔数(Magic)", fmt.Sprintf("0x%04x", h.Magic)},                                                    // Magic
						{"主链接器版本(MajorLinkerVersion)", fmt.Sprintf("0x%02x", h.MajorLinkerVersion)},                      // MajorLinkerVersion
						{"次链接器版本(MinorLinkerVersion)", fmt.Sprintf("0x%02x", h.MinorLinkerVersion)},                      // MinorLinkerVersion
						{"代码大小(SizeOfCode)", fmt.Sprintf("0x%08x", h.SizeOfCode)},                                        // SizeOfCode
						{"已初始化数据大小(SizeOfInitializedData)", fmt.Sprintf("0x%08x", h.SizeOfInitializedData)},              // SizeOfInitializedData
						{"未初始化数据大小(SizeOfUninitializedData)", fmt.Sprintf("0x%08x", h.SizeOfUninitializedData)},          // SizeOfUninitializedData
						{"入口点地址(AddressOfEntryPoint)", fmt.Sprintf("0x%08x", h.AddressOfEntryPoint)},                     // AddressOfEntryPoint
						{"代码基址(BaseOfCode)", fmt.Sprintf("0x%08x", h.BaseOfCode)},                                        // BaseOfCode
						{"数据基址(BaseOfData)", fmt.Sprintf("0x%08x", h.BaseOfData)},                                        // BaseOfData
						{"映像基址(ImageBase)", fmt.Sprintf("0x%08x", h.ImageBase)},                                          // ImageBase
						{"节对齐方式(SectionAlignment)", fmt.Sprintf("0x%08x", h.SectionAlignment)},                           // SectionAlignment
						{"文件对齐方式(FileAlignment)", fmt.Sprintf("0x%08x", h.FileAlignment)},                                // FileAlignment
						{"操作系统版本(主)(MajorOperatingSystemVersion)", fmt.Sprintf("0x%04x", h.MajorOperatingSystemVersion)}, // MajorOperatingSystemVersion
						{"操作系统版本(次)(MinorOperatingSystemVersion)", fmt.Sprintf("0x%04x", h.MinorOperatingSystemVersion)}, // MinorOperatingSystemVersion
						{"映像版本(主)(MajorImageVersion)", fmt.Sprintf("0x%04x", h.MajorImageVersion)},                       // MajorImageVersion
						{"映像版本(次)(MinorImageVersion)", fmt.Sprintf("0x%04x", h.MinorImageVersion)},                       // MinorImageVersion
						{"子系统版本(主)(MajorSubsystemVersion)", fmt.Sprintf("0x%04x", h.MajorSubsystemVersion)},              // MajorSubsystemVersion
						{"子系统版本(次)(MinorSubsystemVersion)", fmt.Sprintf("0x%04x", h.MinorSubsystemVersion)},              // MinorSubsystemVersion
						{"Win32版本值(Win32VersionValue)", fmt.Sprintf("0x%08x", h.Win32VersionValue)},                      // Win32VersionValue
						{"映像大小(SizeOfImage)", fmt.Sprintf("0x%08x", h.SizeOfImage)},                                      // SizeOfImage
						{"头部大小(SizeOfHeaders)", fmt.Sprintf("0x%08x", h.SizeOfHeaders)},                                  // SizeOfHeaders
						{"校验和(CheckSum)", fmt.Sprintf("0x%08x", h.CheckSum)},                                             // CheckSum
						{"子系统(Subsystem)", fmt.Sprintf("0x%04x", h.Subsystem)},                                           // Subsystem
						{"DLL特征(DllCharacteristics)", fmt.Sprintf("0x%04x", h.DllCharacteristics)},                       // DllCharacteristics
						{"堆栈保留大小(SizeOfStackReserve)", fmt.Sprintf("0x%08x", h.SizeOfStackReserve)},                      // SizeOfStackReserve
						{"堆栈提交大小(SizeOfStackCommit)", fmt.Sprintf("0x%08x", h.SizeOfStackCommit)},                        // SizeOfStackCommit
						{"堆保留大小(SizeOfHeapReserve)", fmt.Sprintf("0x%08x", h.SizeOfHeapReserve)},                         // SizeOfHeapReserve
						{"堆提交大小(SizeOfHeapCommit)", fmt.Sprintf("0x%08x", h.SizeOfHeapCommit)},                           // SizeOfHeapCommit
						{"加载标志(LoaderFlags)", fmt.Sprintf("0x%08x", h.LoaderFlags)},                                      // LoaderFlags
						{"RVA和大小数量(NumberOfRvaAndSizes)", fmt.Sprintf("0x%08x", h.NumberOfRvaAndSizes)},                  // NumberOfRvaAndSizes
					}

				case model.OptionHeader64:
					baseEntry.SetText(fmt.Sprintf("0x%X", h.ImageBase))
					entrypointEntry.SetText(fmt.Sprintf("0x%X/0x%X", h.ImageBase+uint64(h.AddressOfEntryPoint), h.AddressOfEntryPoint))
					SFAlignmentEntry.SetText(fmt.Sprintf("0x%X/0x%X", h.SectionAlignment, h.FileAlignment))
					datasetcion = h.DataDirectory
					optiondata = [][]string{
						{"魔数(Magic)", fmt.Sprintf("0x%04x", h.Magic)},                                                    // Magic
						{"主链接器版本(MajorLinkerVersion)", fmt.Sprintf("0x%02x", h.MajorLinkerVersion)},                      // MajorLinkerVersion
						{"次链接器版本(MinorLinkerVersion)", fmt.Sprintf("0x%02x", h.MinorLinkerVersion)},                      // MinorLinkerVersion
						{"代码大小(SizeOfCode)", fmt.Sprintf("0x%08x", h.SizeOfCode)},                                        // SizeOfCode
						{"已初始化数据大小(SizeOfInitializedData)", fmt.Sprintf("0x%08x", h.SizeOfInitializedData)},              // SizeOfInitializedData
						{"未初始化数据大小(SizeOfUninitializedData)", fmt.Sprintf("0x%08x", h.SizeOfUninitializedData)},          // SizeOfUninitializedData
						{"入口点地址(AddressOfEntryPoint)", fmt.Sprintf("0x%08x", h.AddressOfEntryPoint)},                     // AddressOfEntryPoint
						{"代码基址(BaseOfCode)", fmt.Sprintf("0x%08x", h.BaseOfCode)},                                        // BaseOfCode
						{"映像基址(ImageBase)", fmt.Sprintf("0x%08x", h.ImageBase)},                                          // ImageBase
						{"节对齐方式(SectionAlignment)", fmt.Sprintf("0x%08x", h.SectionAlignment)},                           // SectionAlignment
						{"文件对齐方式(FileAlignment)", fmt.Sprintf("0x%08x", h.FileAlignment)},                                // FileAlignment
						{"操作系统版本(主)(MajorOperatingSystemVersion)", fmt.Sprintf("0x%04x", h.MajorOperatingSystemVersion)}, // MajorOperatingSystemVersion
						{"操作系统版本(次)(MinorOperatingSystemVersion)", fmt.Sprintf("0x%04x", h.MinorOperatingSystemVersion)}, // MinorOperatingSystemVersion
						{"映像版本(主)(MajorImageVersion)", fmt.Sprintf("0x%04x", h.MajorImageVersion)},                       // MajorImageVersion
						{"映像版本(次)(MinorImageVersion)", fmt.Sprintf("0x%04x", h.MinorImageVersion)},                       // MinorImageVersion
						{"子系统版本(主)(MajorSubsystemVersion)", fmt.Sprintf("0x%04x", h.MajorSubsystemVersion)},              // MajorSubsystemVersion
						{"子系统版本(次)(MinorSubsystemVersion)", fmt.Sprintf("0x%04x", h.MinorSubsystemVersion)},              // MinorSubsystemVersion
						{"Win32版本值(Win32VersionValue)", fmt.Sprintf("0x%08x", h.Win32VersionValue)},                      // Win32VersionValue
						{"映像大小(SizeOfImage)", fmt.Sprintf("0x%08x", h.SizeOfImage)},                                      // SizeOfImage
						{"头部大小(SizeOfHeaders)", fmt.Sprintf("0x%08x", h.SizeOfHeaders)},                                  // SizeOfHeaders
						{"校验和(CheckSum)", fmt.Sprintf("0x%08x", h.CheckSum)},                                             // CheckSum
						{"子系统(Subsystem)", fmt.Sprintf("0x%04x", h.Subsystem)},                                           // Subsystem
						{"DLL特征(DllCharacteristics)", fmt.Sprintf("0x%04x", h.DllCharacteristics)},                       // DllCharacteristics
						{"堆栈保留大小(SizeOfStackReserve)", fmt.Sprintf("0x%08x", h.SizeOfStackReserve)},                      // SizeOfStackReserve
						{"堆栈提交大小(SizeOfStackCommit)", fmt.Sprintf("0x%08x", h.SizeOfStackCommit)},                        // SizeOfStackCommit
						{"堆保留大小(SizeOfHeapReserve)", fmt.Sprintf("0x%08x", h.SizeOfHeapReserve)},                         // SizeOfHeapReserve
						{"堆提交大小(SizeOfHeapCommit)", fmt.Sprintf("0x%08x", h.SizeOfHeapCommit)},                           // SizeOfHeapCommit
						{"加载标志(LoaderFlags)", fmt.Sprintf("0x%08x", h.LoaderFlags)},                                      // LoaderFlags
						{"RVA和大小数量(NumberOfRvaAndSizes)", fmt.Sprintf("0x%08x", h.NumberOfRvaAndSizes)},                  // NumberOfRvaAndSizes
					}
				}

			}
		}
	}()

	// 将所有元素按垂直布局排列
	w.SetContent(container.NewVBox(
		c1, c2, c3, c4, c5, c6, Space,
	))
	w.SetIcon(icon)

	w.ShowAndRun()
}
func containsIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}
func isDLLFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".dll")
}
func openHexViewerWindow(a fyne.App, lines []string) {
	w7 := a.NewWindow("16进制查看器")
	w7.Resize(fyne.NewSize(600, 600)) // 设置新窗口大小
	w7.SetIcon(icon)
	// 创建列表项模板
	list := widget.NewList(
		func() int {
			return len(lines)
		},
		func() fyne.CanvasObject {
			// 每一行使用一个标签显示
			label := widget.NewLabel("")
			label.Wrapping = fyne.TextWrapOff
			label.TextStyle = fyne.TextStyle{Monospace: true} // 设置为等宽字体
			return label
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			// 设置每一行的内容
			o.(*widget.Label).SetText(lines[i])
		},
	)

	// 创建滚动容器以支持大文件的滚动查看
	scroll := container.NewScroll(list)
	scroll.SetMinSize(fyne.NewSize(800, 600))

	// 设置新窗口的内容为滚动容器
	w7.SetContent(scroll)

	// 显示新窗口
	w7.Show()
}
