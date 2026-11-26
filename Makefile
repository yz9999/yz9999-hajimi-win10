APP_NAME := 哈基米
APP_VERSION := 0.2.0
EXECUTABLE_NAME := Hajimi
BUILD_CONFIG := release
DIST_DIR := dist
APP_BUNDLE := $(DIST_DIR)/$(APP_NAME).app

ARCHS ?= $(shell uname -m)
SWIFT_ARCH_FLAGS := $(foreach arch,$(ARCHS),--arch $(arch))
ARCHIVE_FLAVOR := $(if $(word 2,$(ARCHS)),universal,$(firstword $(ARCHS)))
HAJIMI_TLS_BACKEND ?= openssl
export HAJIMI_TLS_BACKEND
export MACOSX_DEPLOYMENT_TARGET := 13.0

ifeq ($(words $(ARCHS)),1)
BUILD_DIR := .build/$(ARCHS)-apple-macosx/$(BUILD_CONFIG)
else
BUILD_DIR := .build/apple/Products/$(if $(filter release,$(BUILD_CONFIG)),Release,Debug)
endif

THEMES_SRC := $(if $(wildcard SharedAssets/Themes),SharedAssets/Themes,Resources/Themes)

.PHONY: all native-core build build-slim app app-slim icon test verify archive clean run

all: app

native-core:
	HAJIMI_ARCHS="$(ARCHS)" HAJIMI_TLS_BACKEND="$(HAJIMI_TLS_BACKEND)" ./scripts/build_native_core.sh

build: native-core
	swift build -c $(BUILD_CONFIG) $(SWIFT_ARCH_FLAGS) --product $(EXECUTABLE_NAME)
	swift build -c $(BUILD_CONFIG) $(SWIFT_ARCH_FLAGS) --product HajimiHelper

build-slim: build

icon:
	python3 scripts/generate_icon.py

app: build icon
	rm -rf "$(APP_BUNDLE)"
	mkdir -p "$(APP_BUNDLE)/Contents/MacOS" "$(APP_BUNDLE)/Contents/Resources"
	cp "$(BUILD_DIR)/$(EXECUTABLE_NAME)" "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	cp Resources/Info.plist "$(APP_BUNDLE)/Contents/Info.plist"
	cp Resources/Hajimi.icns "$(APP_BUNDLE)/Contents/Resources/Hajimi.icns"
	cp Resources/ThirdPartyNotices.txt "$(APP_BUNDLE)/Contents/Resources/ThirdPartyNotices.txt"
	cp -R "$(THEMES_SRC)" "$(APP_BUNDLE)/Contents/Resources/Themes"
	cp "$(BUILD_DIR)/HajimiHelper" "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	chmod +x "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	chmod +x "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	./scripts/codesign_app.sh "$(APP_BUNDLE)"
	@echo "Built $(APP_BUNDLE) ($(ARCHS), TLS=$(HAJIMI_TLS_BACKEND))"

app-slim: app

test: build
	"$(BUILD_DIR)/$(EXECUTABLE_NAME)" --self-test
	"$(BUILD_DIR)/HajimiHelper" --self-test

verify:
	@if [ ! -d "$(APP_BUNDLE)" ]; then $(MAKE) app ARCHS="$(ARCHS)" BUILD_CONFIG="$(BUILD_CONFIG)" HAJIMI_TLS_BACKEND="$(HAJIMI_TLS_BACKEND)"; fi
	file "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)"
	file "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"
	@for arch in $(ARCHS); do \
		for binary in "$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" "$(APP_BUNDLE)/Contents/Resources/HajimiHelper"; do \
			/usr/bin/lipo -archs "$$binary" | /usr/bin/grep -qw "$$arch" \
				|| { echo "$$binary is missing the $$arch slice"; exit 1; }; \
		done; \
	done
	@echo "Architecture slices verified: $(ARCHS)"
	/usr/bin/codesign --verify --deep --strict --verbose=2 "$(APP_BUNDLE)"
	/usr/bin/plutil -lint "$(APP_BUNDLE)/Contents/Info.plist"
	"$(APP_BUNDLE)/Contents/MacOS/$(EXECUTABLE_NAME)" --self-test
	"$(APP_BUNDLE)/Contents/Resources/HajimiHelper" --self-test

archive:
	@if [ ! -d "$(APP_BUNDLE)" ]; then $(MAKE) app ARCHS="$(ARCHS)" BUILD_CONFIG="$(BUILD_CONFIG)" HAJIMI_TLS_BACKEND="$(HAJIMI_TLS_BACKEND)"; fi
	rm -f "$(DIST_DIR)/$(APP_NAME)-$(APP_VERSION)-$(ARCHIVE_FLAVOR).zip"
	/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$(APP_BUNDLE)" "$(DIST_DIR)/$(APP_NAME)-$(APP_VERSION)-$(ARCHIVE_FLAVOR).zip"

run: app
	open "$(APP_BUNDLE)"

clean:
	swift package clean
	rm -rf "$(DIST_DIR)" Resources/Hajimi.icns Resources/Hajimi.iconset
