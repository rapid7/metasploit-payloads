# Building the Java and Android Meterpreter

1. Install Maven and Java, this will depend on your OS
1. Download the [Android SDK](https://developer.android.com/sdk/index.html)
1. Install Android SDK Platforms 3, 10 and 19, and update the "Android SDK Tools" and "Android SDK Platform-tools"
1. Compile the Android and Java Meterpreter, which deploys to the `../metasploit-framework` folder
```
mvn package -Dandroid.sdk.path=/path/to/android-sdk -Dandroid.release=true -P deploy
```
Next time you run `msfconsole`, you should see: `WARNING: Local files may be incompatible with the Metasploit Framework`.
This means that msfconsole is now using your newly built version of the Java and Android Meterpreter :)

## Building on Docker

Ensure that both the `metasploit-payloads` and `metasploit-framework` folders co-exist beside eachother:
```
$ ls working_directory
metasploit-framework
metasploit-payloads
```

Next you can download a pre-built Docker image from [Rapid7's Docker Hub account](https://hub.docker.com/u/rapid7):
```
docker pull rapid7/msf-ubuntu-x64-meterpreter:latest
```

Or this Docker image can be built manually:
```
cd working_directory/metasploit-payloads/docker
docker build -t rapid7/msf-ubuntu-x64-meterpreter:latest .
```

Next run the Docker image as a container and mount the `working_directory`.
This interactive shell will allow you to compile the Android and Java Meterpreter, and deploy
to the `../metasploit-framework` folder as normal:
```
cd working_directory
docker run --rm  -it -w $(pwd) -v $(pwd):$(pwd) rapid7/msf-ubuntu-x64-meterpreter:latest /bin/bash

cd metasploit-payloads/java
make android
```

## Building on OSX
```
brew cask install caskroom/versions/java8
brew cask install android-sdk
brew install maven
sdkmanager --licenses
sdkmanager "platforms;android-3"
sdkmanager "platforms;android-10"
sdkmanager "platforms;android-19"

#cd metasploit-payloads/java
mvn package -Dandroid.sdk.path=/usr/local/share/android-sdk -Dandroid.release=true -P deploy
```

## Compiling JavaPayload and Java Meterpreter manually

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
`../../metasploit-framework`, but for example (with Kali Linux)

`/usr/share/metasploit-framework/`, set the deploy.path directive like so:

```
mvn -D deploy.path=/usr/share/metasploit-framework -P deploy package
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



