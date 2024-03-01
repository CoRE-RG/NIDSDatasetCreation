all: checkmakefiles
	cd src && $(MAKE)

clean: checkmakefiles
	cd src && $(MAKE) clean

cleanall: checkmakefiles
	cd src && $(MAKE) MODE=release clean
	cd src && $(MAKE) MODE=debug clean
	rm -f src/Makefile

INET_PROJ = $(shell inet_root)

ifeq ($(MODE), debug)
	DBG_SUFFIX=_dbg
else
	DBG_SUFFIX=
endif
MAKEMAKE_OPTIONS := -f --deep --no-deep-includes -O out -KINET_PROJ=../../inet -I. -I$(INET_PROJ)/src/ -L$$\(INET_PROJ\)/out/$$\(CONFIGNAME\)/src -lINET$(DBG_SUFFIX) 

makefiles: makefiles-so

makefiles-so: checkenvir
	cd src && opp_makemake --make-so $(MAKEMAKE_OPTIONS)

makefiles-lib: checkenvir
	cd src && opp_makemake --make-lib $(MAKEMAKE_OPTIONS)

makefiles-exe: checkenvir
	cd src && opp_makemake $(MAKEMAKE_OPTIONS)

checkenvir:
	@if [ "$(INET_PROJ)" = "" ]; then \
	echo; \
	echo '==========================================================================='; \
	echo '<inet_root>/setenv is not sourced. Please change to the INET root directory'; \
	echo 'and type "source setenv" to initialize the environment!'; \
	echo '==========================================================================='; \
	echo; \
	exit 1; \
	fi

checkmakefiles:
	@if [ ! -f src/Makefile ]; then \
	echo; \
	echo '======================================================================='; \
	echo 'src/Makefile does not exist. Please use "make makefiles" to generate it!'; \
	echo '======================================================================='; \
	echo; \
	exit 1; \
	fi
