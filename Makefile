all	:
	./build.sh

clean	:
	make -f Makefile.all clean

install	:
	./build.sh install

deinstall	:
	make -f Makefile.all deinstall

uninstall	:	deinstall
