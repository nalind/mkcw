GO = go
BATS = bats

all: mkcw entrypoint

mkcw: cmd/mkcw/*.go *.go
	$(GO) build -o $@ ./cmd/mkcw

entrypoint: cmd/entrypoint/*.c
	$(CC) -Os -s -static -o $@ $^

clean:
	$(RM) mkcw entrypoint mkcw.test

test:
	$(GO) test
	$(BATS) ./tests
