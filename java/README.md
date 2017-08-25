## Compiling JavaPayload and Java Meterpreter

To compile JavaPayload (a Java stager / code loader) and Java Meterpreter for
Metasploit, you need Maven 3.1 or above (Maven 3.5 works at the time of this
writing), and a copy of JDK 8.0 or later. Ensure that `mvn` and `javac` are in
your path and work. Then run

```
mvn package
```

to package all the files needed for Java meterpreter. The two files that you will be generated are:

```
meterpreter/meterpreter/target/meterpreter.jar
meterpreter/stdapi/target/ext_server_stdapi.jar
```

To get Metasploit to use these files, you need to place them in a place where
it can find them. To automatically build and install these files into
Metasploit Framework for testing, run:

```
mvn -P deploy package
```

This will package all the files and copy them into the correct place for
Metasploit, assuming that the metasploit-framework repository is checked out in
an adjacent directory to this one. (`../../metasploit-framework/data/java`). If
you get spurious compilation errors, make sure that there is an exclude rule in
your antivirus for the Metasploit directory (or that your antivirus is
disabled).

If the path to your metasploit framework repository is not
`../../metasploit-framework`, but for example
`/opt/metasploit-framework/framework`, set the deploy.path directive like so:

```
mvn -D deploy.path=/opt/metasploit-framework/framework -P deploy package
```

When you are editing this or any other Meterpreter, you will want to make sure
that your copy of metasploit-framework is also up-to-date. We occasionally
update the network protocol between Metasploit and its Payloads, and if the two
do not match, things will probably not work. Metasploit will warn you the first
time it stages a development payload that it is doing so, and that the payload
and Metasploit framework may be incompatible.

Each time you make a change to your code, you must build and deploy the files
into metasploit-framework for it to see the updates. It is not necessary to
restart msfconsole when updating payloads however, as they are read from disk
each time. So, a reasonable strategy when debugging is to leave msfconsole
running with `exploit/multi/handler`, and just install and restage payloads as
needed.

When you are done editing and want to revert Metasploit to use the builtin
payloads, simply delete `data/meterpreter/*.jar` and `data/meterpreter/java`
from your Metasploit framework directory. It will then fall back to the
versions bundled with the metasploit-payloads Ruby gem.

# IDE Support

In case you want to edit/debug JavaPayload for Metasploit or Java Meterpreter
with an IDE, Maven provides plugins to auto-generate project files for your
favourite environment (at least for Eclipse, Netbeans or IntelliJ).

I use Eclipse, so to generate project files I use

```
mvn eclipse:eclipse
```

This will generate project files that can be imported via

**File->Import->Existing Projects into Workspace**

into your Eclipse workspace.

(Note that if this is your first Maven project you want to use in Eclipse, you
also have to run

```
mvn -Declipse.workspace=/path/to/your/workspace eclipse:configure-workspace
```

to set up path variables like `M2_REPO` to point to the correct location.)

For NetBeans or IntelliJ IDEA, refer to the documentation at

http://maven.apache.org/netbeans-module.html
http://maven.apache.org/plugins/maven-idea-plugin/

## Android

1. Download the [Android SDK](https://developer.android.com/sdk/index.html), and the [Android NDK](https://developer.android.com/tools/sdk/ndk/index.html) somewhere
2. Launch the `sdk/tool/android` program
3. Install API version 10 and 19, and update the "Android SDK Tools" and "Android SDK Platform-tools"
4. Compile android meterpreter:

```
mvn package -Dandroid.sdk.path=/path/to/android-sdk -Dandroid.ndk.path=/path/to/android-ndk -Dandroid.release=true -P deploy
```



