# JavaPayload4Metasploit - Single payload loader class to be used in the Metasploit project

*© 2010 Michael 'mihi' Schierl, `<schierlm at users dot sourceforge dot
net>`*

## Introduction

The [JavaPayload](http://schierlm.users.sourceforge.net/JavaPayload/)s
contain useful payloads written in pure Java. But they assume that the
attacker has a Java VM on their machine, as the builders and stage
handlers are written in Java. In addition, when creating a new payload
class that should reside in a signed jar, the jar has to be re-signed as
classes have changed.

In contrast, this package contains a single *metasploit.Payload* class
which is configured by a property file in the classpath (i. e. in the
same jar). As it is possible to add unsigned resources to a jar without
requiring to re-sign it, and as it is easy to manipulate zip/jar files
from Ruby, this makes it possible to leverage the powers of JavaPayload
from Metasploit which is written in Ruby and not in Java.

## System requirements

Same as JavaPayload. JRE 1.2 on the victim machine is enough `:-)`

On the attacker machine, no Java at all is required.

## How to use the *Payload* class.

The *Payload* class is a standard java main class (i. e. it has a
`public static void main(String[])` method), so the most obvious way to
invoke it is putting it into a Jar file whose manifest's `Main-Class`
attribute is `metasploit.Payload`. The resuling jar can be started using
`java -jar jarfile.jar`. There are 3 example jars available that use
this technique; they are described later.

Alternatively, the main class can of course be called from other
classes, like `metasploit.Payload.main(null);`, as the arguments
parameter is ignored. Note that in a sandboxed environment the caller
needs to have all permissions, and also the *Payload* class has to be
loaded with all permissions. In case there is untrusted code in the
stack trace (but the direct caller has all permissions), the call has to
be wrapped in a
[doPrivileged](http://download.oracle.com/javase/1.4.2/docs/api/java/security/AccessController.html#doPrivileged\(java.security.PrivilegedExceptionAction\))
call (like it is done in the several well known public exploits for
CVE-2008-5353).

Once loaded, the class will lookup a file called `/metasploit.dat` from
the class path and load it as a [Property
file](http://download.oracle.com/javase/1.4.2/docs/api/java/util/Properties.html#load\(java.io.InputStream\))
(basically a text file with `Name=value` lines, but note that some
special characters need escaping). If the file cannot be found, default
values are used.

Depending on the property values (see below), the class will then
optionally write itself to disk and spawn a sub-process (once or several
times) to disconnect the payload from the calling process. All temporary
files will be deleted afterwards. (Even on Windows it is possible to
delete a running class file as technically, not the class file but the
Java VM is running).

After that, it will either listen on a port and accept a socket, connect
to an URL (using a protocol like HTTP or HTTPS), create an active socket
connection, or (for debugging purposes) just uses standard input and
standard output; in any case, the resulting input/output streams are
used for the staging

Once the stage is loaded, the streams are handed to the stage. Stages
may require optional parameters (a string) which can be given in the
property file.

When the stage quits, the payload class terminates and cleans up after
itself if needed.

## Supported properties (and their default values)

### `Spawn`(`=0`)

The number of java processes that should be spawned. `0` will run the
payload inside the original process, `1` will spawn once (to continue
running when the original process terminates), and `2` will spawn twice
(on certain popular operating systems it is impossible to obtain parent
process information if the parent process has already died).

### `Executable`(`=`)

Points to an executable in the class path (next to metasploit.dat),
which will be extracted to a temporary directory (with original
filename), made executable (if needed by the OS) and executed. When this
option is present, no staging will be performed and all options
documented below are ignored.

### `StageParameters`(`=`)

Additional parameters to be used by the stage, regardless whether it was
embedded or not. Only few stages support/require parameters.

### `URL`(`=`)

Load the stage from this URL. The URL will be requested and the
resulting stream will be used for loading the stage classes from. As the
stage's output stream will discard all input, this is only useful with
stages (like Meterpreter) that can communicate via some other means back
to the attacker.

**Note:** If this option is given, LHOST and LPORT are ignored.

### `LPORT`(`=4444`)

Port to listen on or to connect to (if `LHOST` is also set). If
explicitly set to `0`, no connection will be made, but standard
input/output streams will be used instead.

### `LHOST`(`=`)

Host to connect to. If not set, the payload will listen instead.

## Staging protocol

The staging protocol is quite simple. All classes are sent uncompressed
(as they are inside the .jar file). Each class is prefixed by a 32-bit
big-endian size. After the last class, a size of 0 is sent. The classes
will be defined in the order they are sent (i. e. they can only refer to
classes defined before), and the last sent class will be loaded as a
stage.

In case of an embedded stage, no staging is used - the stream is
directly passed to the stage.

## Supported stages (in alphabetical order)

The stages are original
[JavaPayload](http://schierlm.users.sourceforge.net/JavaPayload/) stages
to make updates easier. All stages listed here can be used without
special "Java" tricks (like serialization or JDWP protocol), to easily
use them from Ruby.

### `Meterpreter`

  - **Stage classes**
    javapayload.stage.Stage,
    com.metasploit.meterpreter.MemoryBufferURLConnection,
    com.metasploit.meterpreter.MemoryBufferURLStreamHandler,
    javapayload.stage.Meterpreter

  - **Parameters**
    Optional parameter `NoRedirect` for debugging.

  - **Stage protocol**
    Meterpreter protocol

Loader to load the Java version of Metasploit's own post-exploitation
toolkit.

### `Shell`

  - **Stage classes**
    javapayload.stage.Stage, javapayload.stage.StreamForwarder,
    javapayload.stage.Shell

  - **Parameters**
    Not supported

  - **Stage protocol**
    Plain text

This stager loads /bin/sh on Unix systems and cmd.exe on Windows
systems, and else just behaves like the `Exec` stage.
