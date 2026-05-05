CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDLIBS = -lnetfilter_queue

TARGET = 1m-block
SRCS = main.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
