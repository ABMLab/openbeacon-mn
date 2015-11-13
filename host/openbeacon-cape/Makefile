CC       := gcc
CPPFLAGS := -D_THREAD_SAFE -D_REENTRANT
CFLAGS   := -O3 -lpcap -pthread -W -Wall -Werror -I.
LDLIBS   := 

TARGET   := openbeacon_forwarder
SOURCES  := $(TARGET).c helper.c crc32.c crc16.c findsink.c
OBJECTS  := $(patsubst %.c,%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@

dependencies-debian:
	sudo apt-get install libpcap-dev

clean:
	rm -f $(TARGET) $(OBJECTS) *.core *~
