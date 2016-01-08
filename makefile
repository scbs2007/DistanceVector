CC= gcc
executables = node 
objects = node.o
VPATH = ../sourceCode

.PHONY : clean

all: clean depend

depend: $(objects)
	$(CC) -o node node.o -lpthread

clean:
	-rm -f $(objects) $(executables)
