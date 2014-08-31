# vim: set noexpandtab:

#
# Determina PDB Loader plugin for Interactive Disassembler Pro
#

VERSION  := 1.0

IDASDK   := ../../idasdk51
IDALIB32 := $(IDASDK)/libvc.w32/ida.lib
IDALIB64 := $(IDASDK)/libvc.w64/ida.lib
IDAINC   := $(IDASDK)/include
IDALDR   := $(IDASDK)/ldr

DBGSDK   := C:/Program Files/Debugging Tools for Windows/sdk
DBGINC   := $(DBGSDK)/inc
DBGLIB   := $(DBGSDK)/lib/i386/dbghelp.lib

IDADIR   := /c/Program\ Files/IDA


#
# Build the plugin
#

SOURCES  := detpdb.cpp

PLUGIN32 := plugin/plw/pdb.plw
PLUGIN64 := plugin/p64/pdb.p64

build: $(PLUGIN32) $(PLUGIN64)


#
# Build the 32-bit plugin
#

OBJECTS32 := $(patsubst %.cpp,plugin/plw/%.obj,$(SOURCES))
PDB32     := $(patsubst %.plw,%.pdb,$(PLUGIN32))

$(OBJECTS32): plugin/plw/%.obj: %.cpp
	cl /nologo /O2 /EHsc /W4 /Wp64 /WX /Zi /GS /MT /I '$(DBGINC)' /I '$(IDAINC)' /I '$(IDALDR)' /D "__NT__" /D "__IDP__" /D VERSION=\"$(VERSION)\" /Fo$@ /c $<

$(PLUGIN32): $(OBJECTS32)
	link /nologo /dll /debug /incremental:no /opt:ref /opt:icf /WX /pdb:$(PDB32) /out:$@ /export:PLUGIN '$(DBGLIB)' '$(IDALIB32)' $+

GENERATED += $(OBJECTS32) $(patsubst %.plw,%.lib,$(PLUGIN32)) $(patsubst %.plw,%.exp,$(PLUGIN32)) $(patsubst %.plw,%.ilk,$(PLUGIN32)) vc??.pdb


#
# Build 64-bit plugin
#

OBJECTS64 := $(patsubst %.cpp,plugin/p64/%.obj,$(SOURCES))
PDB64     := $(patsubst %.p64,%.pdb,$(PLUGIN64))

$(OBJECTS64): plugin/p64/%.obj: %.cpp
	cl /nologo /O2 /EHsc /W4 /Wp64 /WX /Zi /GS /MT /I '$(DBGINC)' /I '$(IDAINC)' /I '$(IDALDR)' /D "__NT__" /D "__IDP__" /D "__EA64__" /D VERSION=\"$(VERSION)\" /Fo$@ /c $<

$(PLUGIN64): $(OBJECTS64)
	link /nologo /dll /debug /incremental:no /opt:ref /opt:icf /WX /pdb:$(PDB64) /out:$@ /export:PLUGIN '$(DBGLIB)' '$(IDALIB64)' $+

GENERATED += $(OBJECTS64) $(patsubst %.p64,%.lib,$(PLUGIN64)) $(patsubst %.p64,%.exp,$(PLUGIN64)) $(patsubst %.p64,%.ilk,$(PLUGIN64)) vc??.pdb


#
# Installation
#

install: $(IDADIR)/plugins/pdb.plw $(IDADIR)/plugins/pdb.p64 $(IDADIR)/cfg/detpdb.cfg

$(IDADIR)/plugins/pdb.plw: $(PLUGIN32)
	cp -a $< '$@'

$(IDADIR)/plugins/pdb.p64: $(PLUGIN64)
	cp -a $< '$@'

$(IDADIR)/cfg/detpdb.cfg: detpdb.cfg
	cp -a $< '$@'


#
# Cleaning
#

clean:
	rm -rf $(PLUGIN32) $(PLUGIN64) $(PDB32) $(PDB64) $(GENERATED)

release-clean:
	rm -rf $(GENERATED)

.PHONY: build install clean release-clean
