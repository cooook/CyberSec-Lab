
target = scanner
object = main.o 	\
		 scan.o     \
		ip_parser.o

CFLAGS = -I.  -std=c++11
CXX = g++


$(target): $(object)
	$(CXX) $^ $(CFLAGS) -o $@

%.o:%.cpp
	$(CXX) -c $(CFLAGS) $< -o $@

clean:
	rm *.o $(target)