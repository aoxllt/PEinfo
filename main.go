package main

import (
	"log"
	"rev/Dllinject"
	"rev/detect"
	"rev/gui"
	"rev/model"
	"strings"
)

func main() {
	go func() {
		for {
			select {
			case filepath := <-model.C:
				filepath = strings.TrimPrefix(filepath, "file://")
				log.Printf("接收到文件路径: %s\n", filepath)
				model.ResultChan <- detect.Detect(filepath)
			}
		}
	}()
	go func() {
		for {
			select {
			case p := <-model.P:
				Dllinject.InjectDLL(p.Pid, p.Path)
			}
		}
	}()
	gui.Creategui()
}
