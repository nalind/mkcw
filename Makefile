GO = go
BATS = bats

all: mkcw

mkcw: cmd/mkcw/*.go pkg/*/*.go *.go pkg/mkcw/embed/entrypoint.gz
	$(GO) build -o $@ ./cmd/mkcw

ifeq ( $(shell go env GOARCH) , amd64 )
pkg/mkcw/embed/entrypoint: pkg/mkcw/embed/entrypoint.c
	$(CC) -Os -static -o $@ $^
	strip $@
endif

pkg/mkcw/embed/entrypoint.gz: pkg/mkcw/embed/entrypoint
	$(RM) $@
	gzip -k $^

clean:
	$(RM) mkcw pkg/mkcw/embed/entrypoint pkg/mkcw/embed/entrypoint.gz mkcw.test

test:
	$(GO) test
	$(BATS) ./tests
