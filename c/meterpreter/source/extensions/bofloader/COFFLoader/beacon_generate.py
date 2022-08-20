from struct import pack, calcsize
import binascii
import cmd

class BeaconPack:
    def __init__(self):
        self.buffer = b''
        self.size = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addshort(self, short):
        self.buffer += pack("<h", short)
        self.size += 2

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)

    def addWstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self.buffer += pack(fmt, len(s)+2, s)
        self.size += calcsize(fmt)

class MainLoop(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.BeaconPack = BeaconPack()
        self.intro = "Beacon Argument Generator"
        self.prompt = "Beacon>"
    
    def do_addWString(self, text):
        '''addWString String here
        Append the wide string to the text.
        '''
        self.BeaconPack.addWstr(text)
    
    def do_addString(self, text):
        '''addString string here
        Append the utf-8 string here.
        '''
        self.BeaconPack.addstr(text)
    
    def do_generate(self, text):
        '''generate
        Generate the buffer for the BOF arguments
        '''
        outbuffer = self.BeaconPack.getbuffer()
        print(binascii.hexlify(outbuffer))
    
    def do_addint(self, text):
        '''addint integer
        Add an int32_t to the buffer
        '''
        try:
            converted = int(text)
            self.BeaconPack.addint(converted)
        except:
            print("Failed to convert to int\n");

    def do_addshort(self, text):
        '''addshort integer
        Add an uint16_t to the buffer
        '''
        try:
            converted = int(text)
            self.BeaconPack.addshort(converted)
        except:
            print("Failed to convert to short\n");
    
    def do_reset(self, text):
        '''reset
        Reset the buffer here.
        '''
        self.BeaconPack.buffer = b''
        self.BeaconPack.size = 0
    
    def do_exit(self, text):
        '''exit
        Exit the console
        '''
        return True

if __name__ == "__main__":
    cmdloop = MainLoop()
    cmdloop.cmdloop()
