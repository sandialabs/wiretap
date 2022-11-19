# wiretap Makefile
# Double ## are used in the help mesage

VERSION=$(shell git describe --tags --abbrev=0 --always)

# defaults
OS=$(shell go env GOOS)## Target OS
ARCH=$(shell go env GOARCH)## Target architecture
BIN=../bin## Binary location

# env
GOOS=GOOS=$(OS)
GOARCH=GOARCH=$(ARCH)
CGO=CGO_ENABLED=0
ENV=env $(GOOS) $(GOARCH) $(CGO)

# gobuild
GOCMD=go
GOBUILD=$(GOCMD) build

# flags with no arguments
NOARGFLAGS=-trimpath

# output extension
ifeq ($(OS), windows)
    EXT=.exe
else
    EXT=
endif

# ld flags
LDFLAGS=-s -w
LDFLAGS+=-X wiretap/cmd.Version=$(VERSION)

.PHONY: all packed wiretap clean help
.DEFAULT_GOAL := wiretap

## wiretap: Build binary for the specified OS and architecture 
wiretap:
	$(ENV) $(GOBUILD) $(NOARGFLAGS) -o $(BIN)/$@_$(OS)_$(ARCH)$(EXT) -ldflags "$(LDFLAGS)" *.go

## all: Build binaries for every OS/ARCH pair listed in the Makefile
all: 
	$(MAKE) OS=windows ARCH=amd64
	$(MAKE) OS=darwin ARCH=amd64
	$(MAKE) OS=linux ARCH=amd64

## packed: Build and pack all binaries with upx
packed: all
	upx --brute $(BIN)/wiretap_*


## clean: Remove all binaries
clean:
	rm -vf $(BIN)/*

# reference:  https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
## help: Print this message
help:
	@echo "Wiretap Makefile"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-zA-Z_-]+: .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ": |## "}; {printf "  %-30s %s\n", $$2, $$3}'
	@echo ""
	@echo "Variables (KEY=DEFAULT):"
	@grep -E '^[a-zA-Z_-]+=.+?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = "## "}; {printf "  %-30s %s\n", $$1, $$2}'
