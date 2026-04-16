GOOS    := linux
GOARCH  := arm
GOARM   := 7
TARGET  := root@10.0.1.68
BINARY  := emrtd
DEPLOY_DIR := /init/emrtd
USB_DIR := /Volumes/MP_SD

.PHONY: build deploy deploy-binary clean usb

build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=0 \
		go build -ldflags="-s -w" -o $(BINARY) ./cmd/emrtd/

deploy-binary: build
	scp -O $(BINARY) $(TARGET):/tmp/$(BINARY)
	ssh $(TARGET) "mount -o remount,rw / && mkdir -p $(DEPLOY_DIR) && cp /tmp/$(BINARY) $(DEPLOY_DIR)/$(BINARY) && chmod +x $(DEPLOY_DIR)/$(BINARY) && mount -o remount,ro /"

clean:
	rm -f $(BINARY)

usb: build
	install autorun.sh ${USB_DIR}/
	install -d ${USB_DIR}/bin/
	install ${BINARY} ${USB_DIR}/bin/
