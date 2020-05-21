all: meterpreter

clean: meterpreter-x64-clean
	@rm -rf workspace/build && rm -rf output/*.dll

meterpreter: meterpreter-x86 meterpreter-x64

meterpreter-x86: meterpreter-x86-gen meterpreter-x86-build

meterpreter-x86-gen:
	cmake -S workspace -B workspace/build/mingw-x86 -Wno-dev -DBUILD_SNIFFER=NO -DBUILD_ARCH=Win32 -DUSE_STATIC_MSVC_RUNTIMES=ON -DCMAKE_TOOLCHAIN_FILE=i686-w64-mingw32.cmake -DDBGTRACE=ON

meterpreter-x86-build:
	cmake --build workspace/build/mingw-x86 --config Release

meterpreter-x86-clean:
	@rm -rf workspace/build/mingw-x86

meterpreter-x64: meterpreter-x64-gen meterpreter-x64-build

meterpreter-x64-gen:
	cmake -S workspace -B workspace/build/mingw-x64 -Wno-dev -DBUILD_SNIFFER=NO -DBUILD_ARCH=x64 -DUSE_STATIC_MSVC_RUNTIMES=ON -DCMAKE_TOOLCHAIN_FILE=x86_64-w64-mingw32.cmake -DDBGTRACE=ON

meterpreter-x64-build:
	cmake --build workspace/build/mingw-x64 --config Release

meterpreter-x64-clean:
	@rm -rf workspace/build/mingw-x64

install:
	@cp output/*.dll ../../../metasploit-framework/data/meterpreter
