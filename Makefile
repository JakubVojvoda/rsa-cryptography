#
# Simple RSA implementation
# by Jakub Vojvoda [vojvoda@swdeveloper.sk]                
# 2016
# 

NAME = rsa

CXX = g++
CXXFLAGS = -c -O2 -pipe -Wall -W

LDFLAGS = -Wl,-O1
LDLIBS = -lgmp

all: main.o $(NAME)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -o main.o main.cpp

$(NAME): main.o
	$(CXX) $(LDFLAGS) -o $(NAME) main.o $(LDLIBS)

clean:
	rm -f $(NAME) main.o *~


