ADB=${ANDROID_HOME}/platform-tools/adb
ANDROID=${ANDROID_HOME}/tools/android
PACKAGE=com.metasploit.stage

DOCKER_CONTAINER=rapid7/msf-ubuntu-x64-meterpreter:latest

all: android

android:
		mvn package -Dandroid.sdk.path=${ANDROID_HOME} -Dandroid.release=true -P deploy

java:
		mvn package

# Build the Java Meterpreter inside the official build container (no local
# JDK/Maven required). Only the metasploit-payloads checkout is mounted, and
# build artifacts are chowned back to the invoking user. The resulting jars
# land in meterpreter/meterpreter/target and meterpreter/stdapi/target.
docker:
		docker run --rm -v "$(CURDIR)/..":/mp -w /mp/java $(DOCKER_CONTAINER) \
			bash -c "mvn -q package; rc=$$?; chown -R $(shell id -u):$(shell id -g) /mp/java; exit $$rc"

clean:
		mvn clean -Dandroid.sdk.path=/

android-api:
		${ANDROID}
 
android-devices:
		${ADB} devices
 
avd:
		${ANDROID} avd
 
android-run:
		${ADB} shell am start -a android.intent.action.MAIN -n ${PACKAGE}/.MainActivity
 
android-shell:
		${ADB} shell

logcat:
		${ADB} logcat

uninstall:
		${ADB} uninstall ${PACKAGE}
