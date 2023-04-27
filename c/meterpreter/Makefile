ID := $(shell id -u)
DOCKER_CONTAINER=rapid7/msf-ubuntu-x64-meterpreter:latest
COMMON_GEN=-Wno-dev -DUSE_STATIC_MSVC_RUNTIMES=ON
COMMON_GEN_X86=-DCMAKE_TOOLCHAIN_FILE=../toolsets/i686-w64-mingw32.cmake -DBUILD_ARCH=Win32 ${COMMON_GEN}
COMMON_GEN_X64=-DCMAKE_TOOLCHAIN_FILE=../toolsets/x86_64-w64-mingw32.cmake -DBUILD_ARCH=x64 ${COMMON_GEN}
COMMON_BUILD=--config Release

all: meterpreter

clean: meterpreter-x64-clean meterpreter-x86-clean

install:
	@cp -f output/*.dll ../../../metasploit-framework/data/meterpreter

##########################################################################################
### Build all
##########################################################################################

meterpreter: meterpreter-x86 meterpreter-x64

meterpreter-x86: meterpreter-x86-gen meterpreter-x86-build

meterpreter-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-dump-sam -DBUILD_ALL=OFF -DBUILD_PLG_DUMPSAM=ON $(COMMON_GEN_X64)
	@cmake -S workspace -B workspace/build/mingw-x86 $(COMMON_GEN_X86)

meterpreter-x86-build:
	@cmake --build workspace/build/mingw-x64-dump-sam $(COMMON_BUILD)
	@cmake --build workspace/build/mingw-x86 $(COMMON_BUILD)

meterpreter-x86-clean:
	@rm -rf workspace/build/mingw-x86* && rm -rf output/*.x86.dll

meterpreter-x64: meterpreter-x64-gen meterpreter-x64-build

meterpreter-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64 $(COMMON_GEN_X64)

meterpreter-x64-build:
	@cmake --build workspace/build/mingw-x64 $(COMMON_BUILD)

meterpreter-x64-clean:
	@rm -rf workspace/build/mingw-x64* && rm -rf output/*.x64.dll

##########################################################################################
### Component Builds
##########################################################################################

### Metsrv

meterpreter-metsrv: meterpreter-metsrv-x86 meterpreter-metsrv-x64

meterpreter-metsrv-x86: meterpreter-metsrv-x86-gen meterpreter-metsrv-x86-build

meterpreter-metsrv-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-metsrv -DBUILD_ALL=OFF -DBUILD_METSRV=ON $(COMMON_GEN_X86)

meterpreter-metsrv-x86-build:
	@cmake --build workspace/build/mingw-x86-metsrv $(COMMON_BUILD)

meterpreter-metsrv-x64: meterpreter-metsrv-x64-gen meterpreter-metsrv-x64-build

meterpreter-metsrv-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-metsrv -DBUILD_ALL=OFF -DBUILD_METSRV=ON $(COMMON_GEN_X64)

meterpreter-metsrv-x64-build:
	@cmake --build workspace/build/mingw-x64-metsrv $(COMMON_BUILD)

### Stdapi

meterpreter-ext-stdapi: meterpreter-ext-stdapi-x86 meterpreter-ext-stdapi-x64

meterpreter-ext-stdapi-x86: meterpreter-ext-stdapi-x86-gen meterpreter-ext-stdapi-x86-build

meterpreter-ext-stdapi-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-stdapi -DBUILD_ALL=OFF -DBUILD_EXT_STDAPI=ON $(COMMON_GEN_X86)

meterpreter-ext-stdapi-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-stdapi $(COMMON_BUILD)

meterpreter-ext-stdapi-x64: meterpreter-ext-stdapi-x64-gen meterpreter-ext-stdapi-x64-build

meterpreter-ext-stdapi-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-stdapi -DBUILD_ALL=OFF -DBUILD_EXT_STDAPI=ON $(COMMON_GEN_X64)

meterpreter-ext-stdapi-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-stdapi $(COMMON_BUILD)

### Priv

meterpreter-ext-priv: meterpreter-ext-priv-x86 meterpreter-ext-priv-x64

meterpreter-ext-priv-x86: meterpreter-ext-priv-x86-gen meterpreter-ext-priv-x86-build

meterpreter-ext-priv-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-dump-sam -DBUILD_ALL=OFF -DBUILD_PLG_DUMPSAM=ON $(COMMON_GEN_X64)
	@cmake -S workspace -B workspace/build/mingw-x86-ext-priv -DBUILD_ALL=OFF -DBUILD_EXT_PRIV=ON $(COMMON_GEN_X86)

meterpreter-ext-priv-x86-build:
	@cmake --build workspace/build/mingw-x64-dump-sam $(COMMON_BUILD)
	@cmake --build workspace/build/mingw-x86-ext-priv $(COMMON_BUILD)

meterpreter-ext-priv-x64: meterpreter-ext-priv-x64-gen meterpreter-ext-priv-x64-build

meterpreter-ext-priv-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-priv -DBUILD_ALL=OFF -DBUILD_EXT_PRIV=ON $(COMMON_GEN_X64)

meterpreter-ext-priv-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-priv $(COMMON_BUILD)

### Extapi

meterpreter-ext-extapi: meterpreter-ext-extapi-x86 meterpreter-ext-extapi-x64

meterpreter-ext-extapi-x86: meterpreter-ext-extapi-x86-gen meterpreter-ext-extapi-x86-build

meterpreter-ext-extapi-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-extapi -DBUILD_ALL=OFF -DBUILD_EXT_EXTAPI=ON $(COMMON_GEN_X86)

meterpreter-ext-extapi-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-extapi $(COMMON_BUILD)

meterpreter-ext-extapi-x64: meterpreter-ext-extapi-x64-gen meterpreter-ext-extapi-x64-build

meterpreter-ext-extapi-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-extapi -DBUILD_ALL=OFF -DBUILD_EXT_EXTAPI=ON $(COMMON_GEN_X64)

meterpreter-ext-extapi-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-extapi $(COMMON_BUILD)

### Incognito

meterpreter-ext-incognito: meterpreter-ext-incognito-x86 meterpreter-ext-incognito-x64

meterpreter-ext-incognito-x86: meterpreter-ext-incognito-x86-gen meterpreter-ext-incognito-x86-build

meterpreter-ext-incognito-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-incognito -DBUILD_ALL=OFF -DBUILD_EXT_INCOGNITO=ON $(COMMON_GEN_X86)

meterpreter-ext-incognito-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-incognito $(COMMON_BUILD)

meterpreter-ext-incognito-x64: meterpreter-ext-incognito-x64-gen meterpreter-ext-incognito-x64-build

meterpreter-ext-incognito-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-incognito -DBUILD_ALL=OFF -DBUILD_EXT_INCOGNITO=ON $(COMMON_GEN_X64)

meterpreter-ext-incognito-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-incognito $(COMMON_BUILD)

### LanAttacks

meterpreter-ext-lanattacks: meterpreter-ext-lanattacks-x86 meterpreter-ext-lanattacks-x64

meterpreter-ext-lanattacks-x86: meterpreter-ext-lanattacks-x86-gen meterpreter-ext-lanattacks-x86-build

meterpreter-ext-lanattacks-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-lanattacks -DBUILD_ALL=OFF -DBUILD_EXT_LANATTACKS=ON $(COMMON_GEN_X86)

meterpreter-ext-lanattacks-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-lanattacks $(COMMON_BUILD)

meterpreter-ext-lanattacks-x64: meterpreter-ext-lanattacks-x64-gen meterpreter-ext-lanattacks-x64-build

meterpreter-ext-lanattacks-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-lanattacks -DBUILD_ALL=OFF -DBUILD_EXT_LANATTACKS=ON $(COMMON_GEN_X64)

meterpreter-ext-lanattacks-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-lanattacks $(COMMON_BUILD)

### WinPMem

meterpreter-ext-winpmem: meterpreter-ext-winpmem-x86 meterpreter-ext-winpmem-x64

meterpreter-ext-winpmem-x86: meterpreter-ext-winpmem-x86-gen meterpreter-ext-winpmem-x86-build

meterpreter-ext-winpmem-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-winpmem -DBUILD_ALL=OFF -DBUILD_EXT_WINPMEM=ON $(COMMON_GEN_X86)

meterpreter-ext-winpmem-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-winpmem $(COMMON_BUILD)

meterpreter-ext-winpmem-x64: meterpreter-ext-winpmem-x64-gen meterpreter-ext-winpmem-x64-build

meterpreter-ext-winpmem-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-winpmem -DBUILD_ALL=OFF -DBUILD_EXT_WINPMEM=ON $(COMMON_GEN_X64)

meterpreter-ext-winpmem-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-winpmem $(COMMON_BUILD)

### Espia

meterpreter-ext-espia: meterpreter-ext-espia-x86 meterpreter-ext-espia-x64

meterpreter-ext-espia-x86: meterpreter-ext-espia-x86-gen meterpreter-ext-espia-x86-build

meterpreter-ext-espia-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-espia -DBUILD_ALL=OFF -DBUILD_EXT_ESPIA=ON $(COMMON_GEN_X86)

meterpreter-ext-espia-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-espia $(COMMON_BUILD)

meterpreter-ext-espia-x64: meterpreter-ext-espia-x64-gen meterpreter-ext-espia-x64-build

meterpreter-ext-espia-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-espia -DBUILD_ALL=OFF -DBUILD_EXT_ESPIA=ON $(COMMON_GEN_X64)

meterpreter-ext-espia-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-espia $(COMMON_BUILD)

### Unhook

meterpreter-ext-unhook: meterpreter-ext-unhook-x86 meterpreter-ext-unhook-x64

meterpreter-ext-unhook-x86: meterpreter-ext-unhook-x86-gen meterpreter-ext-unhook-x86-build

meterpreter-ext-unhook-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-unhook -DBUILD_ALL=OFF -DBUILD_EXT_UNHOOK=ON $(COMMON_GEN_X86)

meterpreter-ext-unhook-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-unhook $(COMMON_BUILD)

meterpreter-ext-unhook-x64: meterpreter-ext-unhook-x64-gen meterpreter-ext-unhook-x64-build

meterpreter-ext-unhook-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-unhook -DBUILD_ALL=OFF -DBUILD_EXT_UNHOOK=ON $(COMMON_GEN_X64)

meterpreter-ext-unhook-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-unhook $(COMMON_BUILD)

### Kiwi

meterpreter-ext-kiwi: meterpreter-ext-kiwi-x86 meterpreter-ext-kiwi-x64

meterpreter-ext-kiwi-x86: meterpreter-ext-kiwi-x86-gen meterpreter-ext-kiwi-x86-build

meterpreter-ext-kiwi-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-kiwi -DBUILD_ALL=OFF -DBUILD_EXT_KIWI=ON $(COMMON_GEN_X86)

meterpreter-ext-kiwi-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-kiwi $(COMMON_BUILD)

meterpreter-ext-kiwi-x64: meterpreter-ext-kiwi-x64-gen meterpreter-ext-kiwi-x64-build

meterpreter-ext-kiwi-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-kiwi -DBUILD_ALL=OFF -DBUILD_EXT_KIWI=ON $(COMMON_GEN_X64)

meterpreter-ext-kiwi-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-kiwi $(COMMON_BUILD)

### PeInjector

meterpreter-ext-peinjector: meterpreter-ext-peinjector-x86 meterpreter-ext-peinjector-x64

meterpreter-ext-peinjector-x86: meterpreter-ext-peinjector-x86-gen meterpreter-ext-peinjector-x86-build

meterpreter-ext-peinjector-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-peinjector -DBUILD_ALL=OFF -DBUILD_EXT_PEINJECTOR=ON $(COMMON_GEN_X86)

meterpreter-ext-peinjector-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-peinjector $(COMMON_BUILD)

meterpreter-ext-peinjector-x64: meterpreter-ext-peinjector-x64-gen meterpreter-ext-peinjector-x64-build

meterpreter-ext-peinjector-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-peinjector -DBUILD_ALL=OFF -DBUILD_EXT_PEINJECTOR=ON $(COMMON_GEN_X64)

meterpreter-ext-peinjector-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-peinjector $(COMMON_BUILD)

### BofLoader

meterpreter-ext-bofloader: meterpreter-ext-bofloader-x86 meterpreter-ext-bofloader-x64

meterpreter-ext-bofloader-x86: meterpreter-ext-bofloader-x86-gen meterpreter-ext-bofloader-x86-build

meterpreter-ext-bofloader-x86-gen:
	@cmake -S workspace -B workspace/build/mingw-x86-ext-bofloader -DBUILD_ALL=OFF -DBUILD_EXT_bofloader=ON $(COMMON_GEN_X86)

meterpreter-ext-bofloader-x86-build:
	@cmake --build workspace/build/mingw-x86-ext-bofloader $(COMMON_BUILD)

meterpreter-ext-bofloader-x64: meterpreter-ext-bofloader-x64-gen meterpreter-ext-bofloader-x64-build

meterpreter-ext-bofloader-x64-gen:
	@cmake -S workspace -B workspace/build/mingw-x64-ext-bofloader -DBUILD_ALL=OFF -DBUILD_EXT_bofloader=ON $(COMMON_GEN_X64)

meterpreter-ext-bofloader-x64-build:
	@cmake --build workspace/build/mingw-x64-ext-bofloader $(COMMON_BUILD)

##########################################################################################
### Container-based Builds
##########################################################################################

docker:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make

docker-container:
	@docker build ../../docker -t $(DOCKER_CONTAINER)

docker-shell:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) bash

docker-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-x64

docker-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-x86

docker-metsrv:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-metsrv

docker-metsrv-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-metsrv-x86

docker-metsrv-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-metsrv-x64

docker-ext-stdapi:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-stdapi

docker-ext-stdapi-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-stdapi-x86

docker-ext-stdapi-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-stdapi-x64

docker-ext-priv:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-priv

docker-ext-priv-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-priv-x86

docker-ext-priv-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-priv-x64

docker-ext-extapi:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-extapi

docker-ext-extapi-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-extapi-x86

docker-ext-extapi-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-extapi-x64

docker-ext-incognito:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-incognito

docker-ext-incognito-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-incognito-x86

docker-ext-incognito-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-incognito-x64

docker-ext-espia:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-espia

docker-ext-espia-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-espia-x86

docker-ext-espia-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-espia-x64

docker-ext-lanattacks:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-lanattacks

docker-ext-lanattacks-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-lanattacks-x86

docker-ext-lanattacks-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-lanattacks-x64

docker-ext-unhook:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-unhook

docker-ext-unhook-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-unhook-x86

docker-ext-unhook-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-unhook-x64

docker-ext-winpmem:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-winpmem

docker-ext-winpmem-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-winpmem-x86

docker-ext-winpmem-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-winpmem-x64

docker-ext-kiwi:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-kiwi

docker-ext-kiwi-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-kiwi-x86

docker-ext-kiwi-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-kiwi-x64

docker-ext-peinjector:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-peinjector

docker-ext-peinjector-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-peinjector-x86

docker-ext-peinjector-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-peinjector-x64

docker-ext-bofloader:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-bofloader

docker-ext-bofloader-x86:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-bofloader-x86

docker-ext-bofloader-x64:
	@docker run -u $(ID):$(ID) -it -v ${PWD}:/meterpreter -w /meterpreter --rm $(DOCKER_CONTAINER) make meterpreter-ext-bofloader-x64
