#########################################################################
# To make PAK-UUCP.EXE with MicroSoft C
# Fredric L. Rice, May 1993
#
#########################################################################

PROJ = PAK-UUCP

#########################################################################
# Define the linker flags
#       /NOI    Ignore Case Differences
#       /NOE    Disable extended dictionary
#       /INC    Incrimental linker
#       /FAR    Employ Far Call Translation
#       /PACKC  Pack adjacent code
#
#########################################################################

LFLAGS = /NOE /INC /FAR /PACKC

#########################################################################
# Define the compile switches
#       /AL     Large memory model
#       /c      Compiled without linking
#       /W4     Highest warning level
#       /Lp     Protected mode
#
#########################################################################

RSWITCHES = /AL /c /W4 /Lp

#########################################################################
# If a *.MAP file is desired, offer the file name here
#
# NUL   if none wanted
#
#########################################################################

MAPFILE  = NUL

#########################################################################
# Where are the *.H header include files located?
#
#########################################################################

INC      = /IC:\C600\INCLUDE

#########################################################################
# Where is the object library to link into the final package?
#
#########################################################################

LLIBS_R  = /NOD:SLIBCE C:\c600\lib\llibce fossil

#########################################################################
# What object files are used to create this project?
#
#########################################################################

OBJS  = $(PROJ).OBJ

#########################################################################
# List all executables for the project here
#
#########################################################################

ALL: $(PROJ).EXE

#########################################################################
# What C files and include files go into making the object files?
#
#########################################################################

$(PROJ).OBJ : $(PROJ).C

#########################################################################
# ?
#
#########################################################################

$(PROJ).BSC :

#########################################################################
# ?
#
#########################################################################

$(PROJ).EXE : $(OBJS)
        ECHO > NUL @<<$(PROJ).LRF
$(RT_OBJS) $(OBJS: = +^
),$@,$(MAPFILE),$(LLIBS_R) $(LIBS),$(DEF_FILE) $(LFLAGS) ;
<<

#########################################################################
# How does this project get linked?
#
#       -a      Link all modules
#       -e      Extended command syntax
#       -c      Case sensitive
#########################################################################

        ILINK -c -a -e "LINK @$(PROJ).LRF" $@

#########################################################################
# How do we compile all OBJ files that are created from C files?
#
#########################################################################

.C.OBJ :
        CL $(RSWITCHES) $(INC) /Gi$(PROJ).mdt /Zi /Od /Fo$@ $<

RUN: $(PROJ).EXE
        $(PROJ).EXE $(RUNFLAGS)

