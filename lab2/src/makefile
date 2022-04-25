CXX = g++
INCLUDE = 
CXXFLAGS = -I.
obj = $(patsubst %.cpp,%.o,$(wildcard *.cpp))
exe = sniffer

$(exe): $(obj)
	$(CXX) $^ $(CXXFLAGS) -o $@

*.o : *.cpp
	$(CXX) $< $(CXXFLAGS) -c -o $@

clean:
	rm $(obj) $(exe)