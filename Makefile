BIN = udpf
PORT = 8125

GOBPF_INCLUDE = cmd/vendor/github.com/iovisor/gobpf/elf/include
GOBPF_INCLUDE_SRC = https://raw.githubusercontent.com/iovisor/gobpf/master/elf/include

.PHONY: build clean debug

build:
	(cd cmd && dep ensure)
	# for reasons go dep doesn't care about those include files :/
	mkdir cmd/vendor/github.com/iovisor/gobpf/elf/include
	curl -s $(GOBPF_INCLUDE_SRC)/bpf.h -o $(GOBPF_INCLUDE)/bpf.h
	curl -s $(GOBPF_INCLUDE_SRC)/bpf_map.h -o $(GOBPF_INCLUDE)/bpf_map.h
	(cd cmd && go build -o ../${BIN})

run: build
	sudo ./udpf -iface lo

debug:
	sudo tc exec bpf dbg

clean:
	-rm *.o
	-rm ${BIN}
	-rm -rf cmd/vendor
