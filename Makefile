CC = gcc
CFLAGS = -Wall
TARGET = pcap-test
INCLUDES = ./
SRCS = pcap-utils.c pcap-funcs.c pcap-test.c
OBJS = $(SRCS:.c=.o)
LDFLAGS = -lpcap

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -std=c11 $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o : %.c
	$(CC) $(CFLAGS) -I $(INCLUDES) -c $< -o $@

clean :
	rm -f $(OBJS) $(TARGET)

.PHONY : all clean