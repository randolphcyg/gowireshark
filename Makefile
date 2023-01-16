CC := gcc

SRC := ./src/
# headers folder (*.h)
INC := ./include/

#libraries folder (*.so)
LIBS := ./libs/

DEPS := ./dep
#  main.c (your main c source code)
MAIN := 
# name of the generated executable
EXEC := main

# the main file can be alone or within the sources folder
sources = $(foreach dir,$(SRC),$(wildcard $(dir)/*.c))

# objects files list
objects := $(patsubst %.c,$(LIBS)/%.o, $(notdir $(sources)))
# dependacies files list
#deps    := $(objects:.o=.d)
deps = $(patsubst  %.c, $(DEPS)/%.d, $(notdir $(sources)))
# compilator's choice
CPPFLAGS := -I $(INC) 
CPPFLAGS += -I ./ 
CPPFLAGS += -I ./include/wireshark/ 
CPPFLAGS += -I /usr/include/glib-2.0/ 
CPPFLAGS += -I /usr/lib/x86_64-linux-gnu/glib-2.0/include/
CPPFLAGS += -I /home/research/Downloads/epan_in_realtime/include/wireshark/include/
CPPFLAGS += -I /usr/include/wireshark/

# compilator's options (you may add some options here)
CFLAGS := -g -Wall -Wextra -pedantic

LDFLAGS=-L$(LIBS) -Wl,-rpath=$(LIBS) -lm -lpcap -lpthread -lwiretap -lwsutil -lwireshark -lglib-2.0

# linking
$(EXEC) : $(objects)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
	$(RM) $(objects) $(deps)
	@echo "Compilation done !"

# compilation from source files
$(LIBS)/%.o: $(SRC)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $^ -o $@

$(DEPS)/%.d: $(SRC)/%.c
	$(CC) $(CPPFLAGS) -MM $< | sed -e 1's,^,$(OBJ)/,' > $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(deps)
endif


# subroutine to remove exec
.PHONY: clean allclean
clean:
	$(RM) $(EXEC)

allclean:
	$(RM) $(objects) $(deps)
	
# dependancies between files
-include $(deps)
