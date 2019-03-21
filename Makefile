CXX = g++
PLUGINDIR=$(shell $(CXX) -print-file-name=plugin)
 
all: csigsafe.so
 
csigsafe.so: csigsafe.o
	$(CXX) $(LDFLAGS) -shared -o $@ $<
 
csigsafe.o : csigsafe.cc csigsafe.hh
	$(CXX) $(CXXFLAGS) -std=c++11 -Wall -fno-rtti -Wno-literal-suffix -I$(PLUGINDIR)/include -fPIC -c -o $@ $<
	
test: csigsafe.so
	cd ./tests && cmake . && make CTEST_OUTPUT_ON_FAILURE=1 test
 
clean:
	rm -f csigsafe.o csigsafe.so 
