DATADIR:=../metasploit-framework/data
METERPDIR:=$(DATADIR)/meterpreter

install: \
	install-c-windows \
    install-java \
    install-php \
    install-python

install-c-windows:
	@echo "Installing Windows payloads"
	@if [ -d c/meterpreter/output/x86 ]; then \
		cp -a c/meterpreter/output/x86/*.dll $(METERPDIR); \
	else \
		echo "Note: Windows 32-bit not built, skipping"; \
	fi
	@if [ -d c/meterpreter/output/x64 ]; then \
		cp -a c/meterpreter/output/x64/*.dll $(METERPDIR); \
	else \
		echo "Note: Windows 64-bit not built, skipping"; \
	fi

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

uninstall:
	rm -fr $(METERPDIR)
	rm -fr $(DATADIR)/java
