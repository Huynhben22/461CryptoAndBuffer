CC= gcc
CFLAGS= --no-pie -g -fno-stack-protector


all: task3.o task4.o task5.o

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *~ *.o
