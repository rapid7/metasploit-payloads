ADB=${ANDROID_HOME}/platform-tools/adb
ANDROID=${ANDROID_HOME}/tools/android
PACKAGE=com.metasploit.stage

all: android

android:
		mvn package -Dandroid.sdk.path=${ANDROID_HOME} -Dandroid.release=true -P deploy

java:
		mvn package

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
