CXXFLAGS	= -O2 -Wall -Wextra
PREFIX		= /usr
SBINDIR		= $(PREFIX)/bin
OBJ			= ntpdos.o

all: ntpdos

%.o: %.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

ntpdos: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~ core ntpdos

install: ntpdos
	install -D -m 0755 ntpdos $(DESTDIR)/$(SBINDIR)/ntpdos
	
uninstall: 
	rm -rf $(DESTDIR)/$(SBINDIR)/ntpdos