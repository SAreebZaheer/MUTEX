# Makefile for libmutex - MUTEX userspace library

CC		= gcc
AR		= ar
CFLAGS		= -Wall -Wextra -O2 -fPIC -I../../linux/include/uapi
LDFLAGS		= -shared
ARFLAGS		= rcs

# Library name and version
LIBNAME		= libmutex
VERSION		= 0.1.0
SONAME		= $(LIBNAME).so.0
SHARED_LIB	= $(LIBNAME).so.$(VERSION)
STATIC_LIB	= $(LIBNAME).a

# Installation directories
PREFIX		?= /usr/local
LIBDIR		= $(PREFIX)/lib
INCLUDEDIR	= $(PREFIX)/include
PKGCONFIGDIR	= $(LIBDIR)/pkgconfig

# Source and object files
SRCS		= libmutex.c
OBJS		= $(SRCS:.c=.o)
HEADERS		= libmutex.h

.PHONY: all clean install uninstall

all: $(SHARED_LIB) $(STATIC_LIB)

# Build shared library
$(SHARED_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -Wl,-soname,$(SONAME) -o $@ $^
	ln -sf $(SHARED_LIB) $(SONAME)
	ln -sf $(SONAME) $(LIBNAME).so

# Build static library
$(STATIC_LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

# Compile object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Install library and headers
install: all
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(PKGCONFIGDIR)
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	ln -sf $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/$(SONAME)
	ln -sf $(SONAME) $(DESTDIR)$(LIBDIR)/$(LIBNAME).so
	install -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/
	@echo "Generating pkg-config file..."
	@echo "prefix=$(PREFIX)" > libmutex.pc
	@echo "exec_prefix=\$${prefix}" >> libmutex.pc
	@echo "libdir=\$${exec_prefix}/lib" >> libmutex.pc
	@echo "includedir=\$${prefix}/include" >> libmutex.pc
	@echo "" >> libmutex.pc
	@echo "Name: libmutex" >> libmutex.pc
	@echo "Description: MUTEX kernel-level proxy userspace library" >> libmutex.pc
	@echo "Version: $(VERSION)" >> libmutex.pc
	@echo "Libs: -L\$${libdir} -lmutex" >> libmutex.pc
	@echo "Cflags: -I\$${includedir}" >> libmutex.pc
	install -m 644 libmutex.pc $(DESTDIR)$(PKGCONFIGDIR)/
	ldconfig -n $(DESTDIR)$(LIBDIR)
	@echo "Installation complete!"

# Uninstall library and headers
uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_LIB)
	rm -f $(DESTDIR)$(LIBDIR)/$(STATIC_LIB)
	rm -f $(DESTDIR)$(LIBDIR)/$(SONAME)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIBNAME).so
	rm -f $(DESTDIR)$(INCLUDEDIR)/libmutex.h
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/libmutex.pc
	@echo "Uninstallation complete!"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(SHARED_LIB) $(STATIC_LIB) $(SONAME) $(LIBNAME).so libmutex.pc
	@echo "Clean complete!"
