CXX=g++
CXXFLAGS=-Wall -Werror -g -std=c++17 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

target: browser

browser: browser.cpp
	$(CXX) $(CXXFLAGS) -o browser browser.cpp $(LDFLAGS)
