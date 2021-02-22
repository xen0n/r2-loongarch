NAME=asm_loongarch
R2_PLUGIN_PATH=$(shell r2 -H R2_USER_PLUGINS)
LIBEXT=$(shell r2 -H LIBEXT)
CFLAGS=-O2 -g -fPIC $(shell pkg-config --cflags r_anal)
LDFLAGS=-shared $(shell pkg-config --libs r_anal)
OBJS=$(NAME).o
LIB=$(NAME).$(LIBEXT)

all: $(LIB)

clean:
	rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	mkdir -p $(R2_PLUGIN_PATH)
	cp -f $(NAME).$(LIBEXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(NAME).$(LIBEXT)
