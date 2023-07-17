GO = go
BATS = bats

all: mkcw

mkcw: cmd/mkcw/*.go pkg/*/*.go *.go pkg/mkcw/embed/entrypoint
	$(GO) build -o $@ ./cmd/mkcw

pkg/mkcw/embed/entrypoint: pkg/mkcw/embed/entrypoint.c
	$(CC) -Os -s -static -o $@ $^

clean:
	$(RM) mkcw entrypoint mkcw.test

test:
	$(GO) test
	$(BATS) ./tests
