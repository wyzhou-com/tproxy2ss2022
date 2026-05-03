CC ?= gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MAIN_NAME = tproxy2ss2022
SS2022_ROOT ?= deps/libss2022-client
SS2022_BUILD_DIR ?= $(SS2022_ROOT)/build
SS2022_LIB = $(SS2022_BUILD_DIR)/libss2022_client.a
SS2022_BLAKE3_LIB = $(SS2022_BUILD_DIR)/deps/BLAKE3/c/libblake3.a
SS2022_WOLFSSL_LIB = $(SS2022_BUILD_DIR)/deps/wolfssl/libwolfssl.a
SS2022_LIBS = $(SS2022_LIB) $(SS2022_BLAKE3_LIB) $(SS2022_WOLFSSL_LIB)

SRCS = src/main.c src/ctx.c src/fakedns_server.c src/netutils.c src/udp_lrucache.c \
       src/fakedns.c src/logutils.c src/mempool.c src/tcp_proxy.c src/udp_proxy.c \
       src/server_selector.c

BUILD_MODE := release
CPPFLAGS   := -D_GNU_SOURCE -DXXH_INLINE_ALL -MMD -MP -Ideps/uthash -Ideps/xxhash -I$(SS2022_ROOT)/include $(EXTRA_CPPFLAGS)
CFLAGS     := -std=c11 -Wall -Wextra -Wvla -pthread -fno-strict-aliasing \
              -ffunction-sections -fdata-sections $(EXTRA_CFLAGS)
LDFLAGS    := -pthread -Wl,--gc-sections $(EXTRA_LDFLAGS)
LDLIBS     := -lm

ifeq ($(DEBUG), 1)
    BUILD_MODE := debug
    CPPFLAGS   += -DFAKEDNS_MRU_STATS
    CFLAGS     += -O0 -g -fsanitize=address,undefined -Wsign-conversion -Wconversion
    LDFLAGS    += -g -fsanitize=address,undefined
else
    CPPFLAGS   += -DNDEBUG
    CFLAGS     += -O3 -flto=auto
    LDFLAGS    += -O3 -flto=auto -s
endif

ifeq ($(STATIC), 1)
    BUILD_MODE := $(BUILD_MODE)-static
    LDFLAGS    += -static
endif

SS2022_CMAKE_BUILD_TYPE := $(if $(filter debug%,$(BUILD_MODE)),Debug,Release)
SS2022_MAKE_C_FLAGS     := $(CPPFLAGS) $(CFLAGS)
SS2022_CMAKE_C_FLAGS    := $(filter -O% -g% -f% -m% -pthread --sysroot=%,$(CFLAGS))
SS2022_CMAKE_LD_FLAGS   := $(LDFLAGS)
SS2022_TARGET_MARCH     := $(lastword $(patsubst -march=%,%,$(filter -march=%,$(SS2022_MAKE_C_FLAGS))))
SS2022_FEATURE_FLAGS    := $(filter -march=% -mcpu=% -mtune=% -msse% -mavx% -maes -mpclmul,$(SS2022_MAKE_C_FLAGS))
SS2022_CMAKE_AR         := $(shell command -v $(CC)-ar 2>/dev/null)
SS2022_CMAKE_NM         := $(shell command -v $(CC)-nm 2>/dev/null)
SS2022_CMAKE_RANLIB     := $(shell command -v $(CC)-ranlib 2>/dev/null)
SS2022_CMAKE_TOOL_ARGS  := $(if $(SS2022_CMAKE_AR),-DCMAKE_AR="$(SS2022_CMAKE_AR)") \
                           $(if $(SS2022_CMAKE_NM),-DCMAKE_NM="$(SS2022_CMAKE_NM)") \
                           $(if $(SS2022_CMAKE_RANLIB),-DCMAKE_RANLIB="$(SS2022_CMAKE_RANLIB)")
SS2022_CONFIG_STAMP     := $(SS2022_BUILD_DIR)/.config_$(SS2022_CMAKE_BUILD_TYPE)
SS2022_STAMP            := $(SS2022_BUILD_DIR)/.built_$(SS2022_CMAKE_BUILD_TYPE)

BUILD_DIR := build/$(BUILD_MODE)
BUILD_CONFIG_STAMP := $(BUILD_DIR)/.config

MAIN = $(BUILD_DIR)/$(MAIN_NAME)
OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS)) $(BUILD_DIR)/deps/libev/ev.o
DEPS = $(OBJS:.o=.d)

.PHONY: all install uninstall clean distclean help
.PHONY: FORCE

all: $(MAIN)

help:
	@echo "Usage: make [TARGET] [OPTIONS]"
	@echo ""
	@echo "Targets:"
	@echo "  all        Build $(MAIN_NAME) (default)"
	@echo "  install    Install $(MAIN_NAME) to \$$(DESTDIR)\$$(BINDIR) (default: $(BINDIR))"
	@echo "  uninstall  Remove $(MAIN_NAME) from \$$(DESTDIR)\$$(BINDIR)"
	@echo "  clean      Remove build artifacts (build/)"
	@echo "  distclean  Remove build artifacts and cmake cache ($(SS2022_BUILD_DIR))"
	@echo "  help       Show this help message"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1    Build with debug symbols and sanitizers (default: 0)"
	@echo "  STATIC=1   Link statically (default: 0)"
	@echo "  CC=...     C compiler to use (default: gcc)"
	@echo "  EXTRA_CFLAGS=...  Extra C flags, propagated to libss2022-client"
	@echo "  EXTRA_LDFLAGS=... Extra linker flags, propagated to libss2022-client"
	@echo "  PREFIX=... Installation prefix (default: /usr/local)"

$(BUILD_CONFIG_STAMP): FORCE
	@mkdir -p $(@D)
	@printf '%s\n' \
	    'CC=$(CC)' \
	    'CPPFLAGS=$(CPPFLAGS)' \
	    'CFLAGS=$(CFLAGS)' \
	    'LDFLAGS=$(LDFLAGS)' \
	    'LDLIBS=$(LDLIBS)' > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm -f $@.tmp; fi

$(MAIN): $(OBJS) $(SS2022_STAMP) $(BUILD_CONFIG_STAMP)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(SS2022_LIBS) $(LDLIBS)

$(SS2022_CONFIG_STAMP): FORCE
	@mkdir -p $(@D)
	@printf '%s\n' \
	    'CC=$(CC)' \
	    'CMAKE_BUILD_TYPE=$(SS2022_CMAKE_BUILD_TYPE)' \
	    'CMAKE_C_FLAGS=$(SS2022_CMAKE_C_FLAGS)' \
	    'CMAKE_EXE_LINKER_FLAGS=$(SS2022_CMAKE_LD_FLAGS)' \
	    'CMAKE_AR=$(SS2022_CMAKE_AR)' \
	    'CMAKE_NM=$(SS2022_CMAKE_NM)' \
	    'CMAKE_RANLIB=$(SS2022_CMAKE_RANLIB)' \
	    'SS2022_TARGET_MARCH=$(SS2022_TARGET_MARCH)' \
	    'SS2022_FEATURE_FLAGS=$(SS2022_FEATURE_FLAGS)' > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; rm -f $(SS2022_STAMP); else rm -f $@.tmp; fi

$(SS2022_STAMP): $(SS2022_ROOT)/CMakeLists.txt $(SS2022_CONFIG_STAMP)
	cmake -S $(SS2022_ROOT) -B $(SS2022_BUILD_DIR) \
	    -DSS2022_BUILD_TESTS=OFF \
	    -DCMAKE_BUILD_TYPE=$(SS2022_CMAKE_BUILD_TYPE) \
	    -DCMAKE_C_COMPILER="$(CC)" \
	    -DCMAKE_C_FLAGS:STRING="$(SS2022_CMAKE_C_FLAGS)" \
	    -DCMAKE_EXE_LINKER_FLAGS:STRING="$(SS2022_CMAKE_LD_FLAGS)" \
	    $(SS2022_CMAKE_TOOL_ARGS) \
	    -DSS2022_TARGET_CFLAGS:STRING="$(SS2022_CMAKE_C_FLAGS)" \
	    -DSS2022_TARGET_MARCH:STRING="$(SS2022_TARGET_MARCH)"
	cmake --build $(SS2022_BUILD_DIR) --target ss2022_client
	@touch $@

$(BUILD_DIR)/src/%.o: src/%.c $(BUILD_CONFIG_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/deps/libev/ev.o: deps/libev/ev.c $(BUILD_CONFIG_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fno-sanitize=undefined -include src/libev_config.h -w -c $< -o $@

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(MAIN) $(DESTDIR)$(BINDIR)/$(MAIN_NAME)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(MAIN_NAME)

clean:
	rm -rf build

distclean: clean
	rm -rf $(SS2022_BUILD_DIR)

-include $(DEPS)
