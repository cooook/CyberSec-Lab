CXX = g++
INCLUDE = 
CXXFLAGS = -I. -std=c++11
obj = $(patsubst %.cpp,%.o,$(wildcard *.cpp))
exe = sniffer

$(exe): $(obj)
	$(CXX) $^ $(CXXFLAGS) -o $@

*.o : *.cpp *.h
	$(CXX) $< $(CXXFLAGS) -c -o $@

clean:
	rm $(obj) $(exe)