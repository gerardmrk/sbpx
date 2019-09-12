BIN_OUT = ./.bin
BIN_SRC = ./cmd

BIN_PREFIX_MACOS = _mac
BIN_PREFIX_LINUX = _linux
BIN_PREFIX_WINDOWS = _windows

GO_CMD = go
GO_GET = $(GO_CMD) get
GO_TEST = $(GO_CMD) test
GO_BUILD = $(GO_CMD) build
GO_CLEAN = $(GO_CMD) clean

GO_BUILD_FLAGS = -s -w
GO_BUILD_TAGS = x

all: bench

test:
	$(GO_TEST) -v ./...

bench:
	$(GO_TEST) -bench .

