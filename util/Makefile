DEBUG = 0

PROGS = img_pulse_test
OLD_PROGS = ph5_test fits_test pfits_test image_test pff_test
    # these require cfitsio, hdf5, or other removed sources

OBJS = image.o

all: $(PROGS)

SRCS = img_pulse_test.cpp

H5_INC = -I/usr/include/hdf5/serial

ifeq ($(DEBUG),1)
CXXFLAGS =  -g -fPIC
else
CXXFLAGS =  -O4 -fPIC
endif

CXX = g++ $(CXXFLAGS) $(H5_INC)

.cpp.o:
	$(CXX) -c -o $*.o $<

img_pulse_test: img_pulse_test.cpp img_pulse.h
	$(CXX) -o img_pulse_test img_pulse_test.cpp

-include Makefile.deps

Makefile.deps: $(SRCS)
	 $(CXX) -MM $(H5_INC) $(SRCS) > Makefile.deps

clean:
	rm -f $(PROGS) *.o
