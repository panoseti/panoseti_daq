CC          = g++
REDIS_LIB_CCFLAGS = -lhiredis
CCFLAGS     = -g -O3 -fPIC -shared -lstdc++ \
    -I. -I$(CUDA_DIR)/include -I/usr/local/include \
    -I ./util \
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
    ./util/pff.cpp \
	./util/image.cpp

INCLUDES = databuf.h compute_thread.h process_frame.h

N_INPUT_BLOCKS=512
N_OUTPUT_BLOCKS=128

all: $(TARGET)

$(TARGET): $(SOURCES) $(INCLUDES)
	$(CC) -o $(TARGET) $(SOURCES) $(CCFLAGS) -DN_INPUT_BLOCKS=$(N_INPUT_BLOCKS) -DN_OUTPUT_BLOCKS=$(N_OUTPUT_BLOCKS)

tags:
	ctags -R .
clean:
	rm -f $(TARGET) tags

.PHONY: all tags clean install install-lib
