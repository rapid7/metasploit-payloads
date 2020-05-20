all: meterpreter

clean: meterpreter-x64-clean
	@rm -rf workspace/build && rm -rf output/*.dll

meterpreter: meterpreter-x64

meterpreter-x64: meterpreter-x64-gen meterpreter-x64-build

meterpreter-x64-gen:
	cmake -G 'Unix Makefiles' -S workspace -B workspace/build/mingw-x64 -Wno-dev -DBUILD_SNIFFER=NO -DBUILD_ARCH=x64 -DSTATIC_LINKAGE=ON -DUSE_STATIC_MSVC_RUNTIMES=ON -DDBGTRACE=ON

meterpreter-x64-build:
	cmake --build workspace/build/mingw-x64 --config Release

meterpreter-x64-clean:
	@rm -rf workspace/build/mingw-x64
