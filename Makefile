DATADIR:=../metasploit-framework/data
METERPDIR:=$(DATADIR)/meterpreter
ANDROIDSDKDIR:=/usr/local/share/android-sdk

install-all: \
	install-windows \
	install-java \
	install-android \
	install-php \
	install-python

install-windows:
		@echo "Installing Windows payloads"
    ifneq ("$(wildcard c/meterpreter/output/*.x86.dll)","")
			@cp c/meterpreter/output/*.x86.dll $(METERPDIR) 
    else
			@echo "Note: Windows 32-bit not built, skipping"
    endif
    ifneq ("$(wildcard c/meterpreter/output/*.x64.dll)","")
			@cp c/meterpreter/output/*.x64.dll $(METERPDIR) 
    else
			@echo "Note: Windows 64-bit not built, skipping"
    endif

install-java:
	@echo "Installing Java payloads"
	@mvn -v >/dev/null 2>&1 || echo "Note: Maven not found, skipping";
	@mvn -v >/dev/null 2>&1 && (cd java; mvn package -Dandroid.release=true -P deploy -q);

install-php: $(METERPDIR)
	@echo "Installing PHP payloads"
	@cp php/meterpreter/*.php $(METERPDIR)

install-python: $(METERPDIR)
	@echo "Installing Python payloads"
	@cp python/meterpreter/*.py $(METERPDIR)

install-android:
	@echo "Installing Android payloads"
	@mvn -v >/dev/null 2>&1 || echo "Note: Maven not found, skipping";
	@mvn -v >/dev/null 2>&1 && (cd java; mvn package -Dandroid.sdk.path=$(ANDROIDSDKDIR) -Dandroid.release=true -P deploy -q);

uninstall:
	rm -fr $(METERPDIR)
	rm -fr $(DATADIR)/java
