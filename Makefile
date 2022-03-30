CC          = g++
REDIS_LIB_CCFLAGS = -lhiredis
CCFLAGS     = -g -O3 -fPIC -shared -lstdc++ -msse4 \
    -I. -I$(CUDA_DIR)/include -I/usr/local/include \
    -I ../util \
    -L. -L/usr/local/lib \
    -lhashpipe -lrt -lm \
    -ldl \
    -Wl,-rpath
TARGET   = hashpipe.so
SOURCES  = net_thread.c \
    compute_thread.c \
    output_thread.c \
    process_frame.c \
    databuf.c \
    ../util/pff.o
#    ../util/image.o

INCLUDES = databuf.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(INCLUDES)
	$(CC) -o $(TARGET) $(SOURCES) $(CCFLAGS)

tags:
	ctags -R .
clean:
	rm -f $(TARGET) tags

.PHONY: all tags clean install install-lib
# vi: set ts=8 noet :
