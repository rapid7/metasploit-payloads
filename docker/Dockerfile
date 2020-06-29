# To build the dev environment.
# docker build -t rapid7/msf-ubuntu-x64-meterpreter:latest .

FROM ubuntu:focal
MAINTAINER Brent Cook <bcook@rapid7.com> (@busterbcook)

ENV DEBIAN_FRONTEND noninteractive

# Other meterpreters
RUN apt-get update && \
	apt-get dist-upgrade -y && \
	apt-get -y install software-properties-common && \
	dpkg --add-architecture i386 && \
	apt-get update && \
  apt-get -y install bison flex gcc gcc-multilib jam make wget \
    ruby rake bundler git \
    mingw-w64-x86-64-dev mingw-w64-i686-dev \
    g++-mingw-w64-i686 g++-mingw-w64-x86-64 \
    gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 \
    cmake \
    maven \
    wine python python3 \
    openjdk-8-jdk \
    php-cli && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN update-java-alternatives --set java-1.8.0-openjdk-amd64

# Android NDK
RUN wget http://dl.google.com/android/ndk/android-ndk-r9d-linux-x86_64.tar.bz2 && \
    tar -xvf android-ndk-r9d-linux-x86_64.tar.bz2 && \
    mv android-ndk-r9d /usr/local/android-ndk && \
	rm android-ndk-r9d-linux-x86_64.tar.bz2

# Android SDK
RUN wget http://dl.google.com/android/android-sdk_r24-linux.tgz && \
    tar -xvf android-sdk_r24-linux.tgz && \
	rm android-sdk_r24-linux.tgz && \
    mv android-sdk-linux /usr/local/android-sdk
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter tools --no-ui -a
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter platform-tools --no-ui -a
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter build-tools-23.0.0 --no-ui -a
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter android-10 --no-ui -a
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter android-19 --no-ui -a
RUN echo y | /usr/local/android-sdk/tools/android update sdk --filter android-3 --no-ui -a

# Pre-cache Maven artifacts
RUN git clone https://github.com/rapid7/metasploit-payloads.git && \
	cd metasploit-payloads/java && make ; cd .. && rm -fr metasploit-payloads

ENV ANDROID_HOME /usr/local/android-sdk
ENV ANDROID_NDK_HOME /usr/local/android-ndk
ENV PATH $PATH:$ANDROID_HOME/tools
ENV PATH $PATH:$ANDROID_HOME/platform-tools
ENV PATH $PATH:$ANDROID_NDK_HOME

ENV JENKINS_HOME /var/jenkins_home
RUN useradd -d "$JENKINS_HOME" -u 1001 -m -s /bin/sh jenkins
VOLUME "$JENKINS_HOME"
RUN chown -R jenkins "$JENKINS_HOME"
