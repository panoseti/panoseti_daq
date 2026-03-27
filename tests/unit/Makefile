CXX      = g++
CXXFLAGS = -std=c++17 -g -Wall -Wextra -Wno-unused-parameter \
           -I../../util \
           -I../../

# Catch2 v3 header/library location (Ubuntu 22.04+: apt install catch2)
CATCH2_INCLUDES = $(shell pkg-config --cflags catch2-with-main 2>/dev/null)
CATCH2_LIBS     = $(shell pkg-config --libs   catch2-with-main 2>/dev/null || echo "-lcatch2-with-main")

SOURCES_UNDER_TEST = ../../util/pff.cpp ../../util/image.cpp

TEST_SOURCES = test_pff.cpp test_image_rotation.cpp test_packet_utils.cpp

TARGET = panoseti_unit_tests

all: $(TARGET)

$(TARGET): $(TEST_SOURCES) $(SOURCES_UNDER_TEST)
	$(CXX) $(CXXFLAGS) $(CATCH2_INCLUDES) -o $@ $^ $(CATCH2_LIBS)

test: $(TARGET)
	./$(TARGET) --reporter compact

clean:
	rm -f $(TARGET)

.PHONY: all test clean
