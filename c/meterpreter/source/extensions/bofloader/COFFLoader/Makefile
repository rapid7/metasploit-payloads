
all: bof bof32
all-dll: dll dll32
debug: debug32 debug64

dll:
	x86_64-w64-mingw32-gcc -shared -Wall -DBUILD_DLL dll.c beacon_compatibility.c COFFLoader.c -o COFFLoader.x64.dll
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

dll32:
	i686-w64-mingw32-gcc -shared -Wall -DBUILD_DLL dll.c beacon_compatibility.c COFFLoader.c -o COFFLoader.x86.dll
	i686-w64-mingw32-gcc -c test.c -o test32.out

bof:
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

bof32:
	i686-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c COFFLoader.c -o COFFLoader32.exe
	i686-w64-mingw32-gcc -c test.c -o test32.out

debug64:
	x86_64-w64-mingw32-gcc -DCOFF_STANDALONE -DDEBUG beacon_compatibility.c COFFLoader.c -o COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c test.c -o test64.out

debug32:
	i686-w64-mingw32-gcc -DCOFF_STANDALONE -DDEBUG beacon_compatibility.c COFFLoader.c -o COFFLoader32.exe
	i686-w64-mingw32-gcc -c test.c -o test32.out

nix:
	gcc -DCOFF_STANDALONE -Wall -DDEBUG beacon_compatibility.c COFFLoader.c -o COFFLoader.out

clean:
	rm -f COFFLoader64.exe COFFLoader32.exe COFFLoader.out
	rm -f test32.out test64.out
	rm -f *.dll
