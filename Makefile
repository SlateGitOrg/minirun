# minirun build and verification targets. `make check` is the single gate:
# formatting, lint (zero findings, for both macOS and Linux builds), type
# checking of every supported GOOS/GOARCH, unit tests with the race
# detector, and the core-logic coverage floor. None of it needs Docker,
# root or network.

GO        ?= go
GOFLAGS   ?= -p=3
export GOFLAGS
COVER_MIN ?= 85
BIN       := bin/minirun

.PHONY: all build check fmt fmt-check lint typecheck test cover integration demo fuzz bench tables clean

all: build

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/minirun

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run ./...
	GOOS=linux golangci-lint run ./...

typecheck:
	$(GO) vet ./...
	GOOS=linux GOARCH=amd64 $(GO) vet ./...
	GOOS=linux GOARCH=arm64 $(GO) vet ./...
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o /dev/null ./cmd/minirun
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o /dev/null ./cmd/minirun

test:
	$(GO) test -race -count=1 ./...

cover:
	sh scripts/coverage.sh $(COVER_MIN)

check: fmt-check lint typecheck test cover

# Real containers in a privileged Linux Docker container; skips cleanly
# without Docker.
integration:
	sh test/integration/run.sh

demo: build
	sh scripts/demo.sh

fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzCompileMatchesEvaluate -fuzztime=60s ./internal/seccomp

bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/seccomp

# Regenerate the syscall tables from golang.org/x/sys.
tables:
	$(GO) run ./internal/seccomp/mktables.go > internal/seccomp/ztables.go.new
	mv internal/seccomp/ztables.go.new internal/seccomp/ztables.go

clean:
	rm -rf bin coverage.out
