package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"text/template"

	"github.com/iovisor/gobpf/elf"
)

const (
	bpfSource    = "bpf.c"
	bpfTemplated = "bpf.templated.c"
	bpfBytecode  = "bpf.o"
)

func compile(cfg *config) (*elf.Module, error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path.Join(dir, bpfTemplated), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// template bpf.c
	t := template.New("bpf.c")
	t, _ = t.ParseFiles(path.Join(dir, bpfSource))
	t.Execute(f, cfg)

	args := []string{
		// include path
		fmt.Sprintf("-I%s", dir),
		fmt.Sprintf("-I%s", path.Join(dir, "include")),
		"-O2",
		"-target", "bpf",
		"-Wall",
		"-Werror",
		"-Wno-address-of-packed-member",
		"-Wno-unknown-warning-option",
		"-c", path.Join(dir, bpfTemplated),
		"-o", path.Join(dir, bpfBytecode),
	}
	log.Printf("clang args: %#v", args)
	// runs in the calling process's current directory.
	cmd := exec.Command("clang", args...)
	combined, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to compile source: %s\n%s", err, combined)
	}

	var secParams = map[string]elf.SectionParams{
		"maps/test": elf.SectionParams{
			PinPath: filepath.Join("udpf", "testgroup1"),
		},
	}
	mod := elf.NewModule(path.Join(dir, bpfBytecode))
	err = mod.Load(secParams)
	if err != nil {
		return nil, fmt.Errorf("error loading module: %s\n%s", err, string(mod.Log()))
	}
	log.Printf("successfully loaded module\n")
	return mod, nil
}
