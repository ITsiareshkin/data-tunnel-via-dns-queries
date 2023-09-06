CC = gcc

.PHONY: subdirs sender receiver other

receiver:
	$(CC) -o dns_receiver receiver/*.c other/*.c

.PHONY: subdirs sender receiver other
sender:
	$(CC) -o dns_sender sender/*.c other/*.c


all:
	$(CC) $(FLAGS) -o dns_receiver receiver/*.c other/*.c
	$(CC) $(FLAGS) -o dns_sender sender/*.c other/*.c

archive:
	tar -cvf xtsiar00.tar other sender receiver README manual.pdf Makefile
