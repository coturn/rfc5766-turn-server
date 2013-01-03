all	:
	./build.sh

clean	:
	make -f Makefile.all clean

install	:
	./build.sh install

deinstall	:	install
	./build.sh deinstall

uninstall	:	deinstall
