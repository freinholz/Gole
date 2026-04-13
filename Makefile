LDFLAGS := -ldflags="-s -w"
SOURCES := main.go common.go cli.go crypt.go kconfig.go holepunch.go server.go client.go
OUT := gole
SWARM_OUT := gole-swarm
ifneq (,$(findstring NT,$(shell uname)))
	OUT := $(OUT).exe
	SWARM_OUT := $(SWARM_OUT).exe
endif
DATE := $(shell date -u +%Y%m%d)

default: $(OUT) $(SWARM_OUT)

$(OUT): $(SOURCES)
	go build $(LDFLAGS) -o $(OUT) $(SOURCES)

# Dedicated swarm binary — built from cmd/swarm, depends on the swarm package.
.PHONY: swarm
swarm: $(SWARM_OUT)
$(SWARM_OUT):
	go build $(LDFLAGS) -o $(SWARM_OUT) ./cmd/swarm

.PHONY: swarm-test
swarm-test:
	go test ./swarm/...

.PHONY: clean
clean:
	@-rm -f $(OUT) $(SWARM_OUT)
	@-rm -f ./client ./server
	@-rm -f ./gtun
	@-rm -f *.exe
	@-rm -f gole_darwin_amd64
	@-rm -f gole-linux-386 gole-linux-amd64
	@-rm -f gole-linux-arm gole-linux-arm64
	@-rm -f gole-linux-mips gole-linux-mipsle
	@-rm -f gole-windows-386.exe gole-windows-amd64.exe
	@-rm -f *.zip

.PHONY: release
release:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o gole-darwin-amd64 $(SOURCES)
	zip gole-darwin-$(DATE).zip gole-darwin-amd64
	rm gole-darwin-amd64

	GOOS=linux GOARCH=386 go build $(LDFLAGS) -o gole-linux-386 $(SOURCES)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o gole-linux-amd64 $(SOURCES)
	GOOS=linux GOARCH=arm go build $(LDFLAGS) -o gole-linux-arm $(SOURCES)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o gole-linux-arm64 $(SOURCES)
	GOOS=linux GOARCH=mips go build $(LDFLAGS) -o gole-linux-mips $(SOURCES)
	GOOS=linux GOARCH=mipsle go build $(LDFLAGS) -o gole-linux-mipsle $(SOURCES)
	zip gole-linux-$(DATE).zip gole-linux-386 gole-linux-amd64 gole-linux-mips gole-linux-mipsle gole-linux-arm gole-linux-arm64
	rm gole-linux-386 gole-linux-amd64 gole-linux-mips gole-linux-mipsle gole-linux-arm gole-linux-arm64

	GOOS=windows GOARCH=386 go build $(LDFLAGS) -o gole-windows-386.exe $(SOURCES)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o gole-windows-amd64.exe $(SOURCES)
	zip gole-windows-$(DATE).zip gole-windows-386.exe gole-windows-amd64.exe
	rm gole-windows-386.exe gole-windows-amd64.exe
