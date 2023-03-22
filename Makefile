GO := go
GO_BUILD = CGO_ENABLED=0 $(GO) build
GO_GENERATE = $(GO) generate
TARGET=xdp-firewall


$(TARGET):
	$(GO_GENERATE)
	$(GO_BUILD) \
		-ldflags "-w -s"

.PHONY: $(TARGET)
