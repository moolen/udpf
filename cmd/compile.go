package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/iovisor/gobpf/elf"
)

func transformBE(input []byte) (output uint32) {
	binary.Read(bytes.NewBuffer(input), binary.BigEndian, &output)
	return
}

func compile(cfg *config) (*elf.Module, error) {
	targetAddr, err := cfg.targetAddr()
	if err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return nil, err
	}
	args := []string{
		// include path
		fmt.Sprintf("-I%s", dir),
		fmt.Sprintf("-I%s", path.Join(dir, "include")),
		// target definitions
		fmt.Sprintf("-DTARGET_ADDR=%d", targetAddr),
		fmt.Sprintf("-DUDP_DEST_PORT=%d", cfg.targetPort),
		"-O2",
		"-target", "bpf",
		"-Wall",
		"-Werror",
		"-Wno-address-of-packed-member",
		"-Wno-unknown-warning-option",
		"-c", bpfSource,
		"-o", bpfBytecode,
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
