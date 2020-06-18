ping: ping.o checksum.o
	gcc -o ping ping.o checksum.o

ping.o: ping.c
	gcc -c -std=gnu99 -pedantic-errors -Wall ping.c

checksum.o: checksum.c
	gcc -c -std=gnu99 -pedantic-errors -Wall checksum.c

clean:
	rm *.o ping
