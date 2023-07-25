GO = go
BATS = bats

all: mkcw

mkcw: cmd/mkcw/*.go pkg/*/*.go *.go pkg/mkcw/embed/entrypoint.gz
	$(GO) build -o $@ ./cmd/mkcw

ifneq ($(shell as --version | grep x86_64),)
pkg/mkcw/embed/entrypoint: pkg/mkcw/embed/entrypoint.s
	$(AS) -o $(patsubst %.s,%.o,$^) $^
	$(LD) -o $@ $(patsubst %.s,%.o,$^)
	strip $@
else
.PHONY: pkg/mkcw/embed/entrypoint
endif

pkg/mkcw/embed/entrypoint.gz: pkg/mkcw/embed/entrypoint
	$(RM) $@
	gzip -k $^

clean:
	$(RM) mkcw pkg/mkcw/embed/entrypoint.o pkg/mkcw/embed/entrypoint pkg/mkcw/embed/entrypoint.gz mkcw.test

test:
	$(GO) test
	$(BATS) ./tests
