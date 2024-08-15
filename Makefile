# Compiler
CC := gcc

# Source and Include directories
SRC := ./
INC := ./include/
LIBS := ./libs/
DEPS := ./deps/

# Output executable name
EXEC := main

# Source files and corresponding object and dependency files
sources := $(wildcard $(SRC)/*.c)
objects := $(patsubst $(SRC)/%.c,$(DEPS)/%.o,$(sources))
deps := $(patsubst $(SRC)/%.c,$(DEPS)/%.d,$(sources))

# Compiler and linker flags
CPPFLAGS := -I $(INC) $(shell pkg-config --cflags glib-2.0)
CPPFLAGS += -I $(INC)/wireshark -I $(INC)/libpcap
CFLAGS := -g -Wall -Wextra -pedantic
LDFLAGS := $(shell pkg-config --libs glib-2.0) -Wl,-rpath,$(LIBS) -L$(LIBS)
LDFLAGS += -lwiretap -lwsutil -lwireshark -lpcap

# Link the object files to create the executable
$(EXEC) : $(objects)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
	$(RM) $(objects) $(deps)
	@echo "Compilation done !"

# Compile source files into object files
$(DEPS)/%.o: $(SRC)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Generate dependency files for each source file
$(DEPS)/%.d: $(SRC)/%.c
	@mkdir -p $(DEPS)
	$(CC) $(CPPFLAGS) -MM $< | sed 's@^\(.*\)\.o:@$(DEPS)/\1.o $(DEPS)/\1.d:@' > $@

# Include dependency files
-include $(deps)

# Clean target to remove the executable
.PHONY: clean
clean:
	$(RM) $(EXEC)
	@echo "Cleaned up!"

# Clean all target to remove the executable, object, and dependency files
.PHONY: allclean
allclean:
	$(RM) $(EXEC) $(objects) $(deps)
	@echo "Cleaned everything!"