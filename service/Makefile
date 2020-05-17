include_dir="/System/Library/Frameworks/Python.framework/Versions/2.7/include/python2.7/"
cc=gcc
service.o: service.c
	cc -o service.o -g service.c -I$(include_dir) -lpython2.7 -lssl -lcrypto

linux: service.c
	cc -o service service.c -g -I/usr/include/python2.7/ -lpython2.7 -lssl -lcrypto

local_check: local_check.c
	cc -o local_check local_check.c -g -I/usr/include/python2.7/ -lpython2.7 -lssl -lcrypto
