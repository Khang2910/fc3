# Target OS/Arch
GOOS := windows
GOARCH := amd64

# Output directories
OUT_DIR := downloads

# Source files
DLL_SRC := client/basic.go
DLL_OUT := $(OUT_DIR)/basic.dll
DLL_NAME := basic

EXE_SRC := victim.go
EXE_OUT := victim.exe

# Default target
all: exe dlls

# Build DLL
dlls: $(DLL_OUT)

$(DLL_OUT): $(DLL_SRC) utils/utils.h | $(OUT_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -buildmode=c-shared -o $(DLL_OUT) $(DLL_SRC)

# Build executable
exe: $(EXE_SRC)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(EXE_OUT) $(EXE_SRC)

# Ensure output dir exists
$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Cleanup
clean:
	rm -f $(EXE_OUT) $(OUT_DIR)/*.dll $(OUT_DIR)/*.h
