GOCMD=go

all:
	GOOS=linux GOARCH=amd64 $(GOCMD) build -o go_sample -ldflags "-s" -gcflags="all=-N -l" go_sample.go