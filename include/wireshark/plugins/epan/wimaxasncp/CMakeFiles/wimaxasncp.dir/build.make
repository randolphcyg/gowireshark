# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /opt/wireshark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /opt/wireshark

# Include any dependencies generated for this target.
include plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/depend.make

# Include the progress variables for this target.
include plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/progress.make

# Include the compile flags for this target's objects.
include plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/flags.make

plugins/epan/wimaxasncp/plugin.c: plugins/epan/wimaxasncp/packet-wimaxasncp.c
plugins/epan/wimaxasncp/plugin.c: tools/make-plugin-reg.py
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating plugins/epan/wimaxasncp/plugin.c"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/python3 /opt/wireshark/tools/make-plugin-reg.py /opt/wireshark/plugins/epan/wimaxasncp plugin packet-wimaxasncp.c

plugins/epan/wimaxasncp/wimaxasncp_dict.c: plugins/epan/wimaxasncp/wimaxasncp_dict.l
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Generating wimaxasncp_dict.c, wimaxasncp_dict_lex.h"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/flex -o/opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict.c --header-file=/opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict_lex.h /opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict.l

plugins/epan/wimaxasncp/wimaxasncp_dict_lex.h: plugins/epan/wimaxasncp/wimaxasncp_dict.c
	@$(CMAKE_COMMAND) -E touch_nocreate plugins/epan/wimaxasncp/wimaxasncp_dict_lex.h

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.o: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/flags.make
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.o: plugins/epan/wimaxasncp/plugin.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.o"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/wimaxasncp.dir/plugin.c.o   -c /opt/wireshark/plugins/epan/wimaxasncp/plugin.c

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wimaxasncp.dir/plugin.c.i"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/epan/wimaxasncp/plugin.c > CMakeFiles/wimaxasncp.dir/plugin.c.i

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wimaxasncp.dir/plugin.c.s"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/epan/wimaxasncp/plugin.c -o CMakeFiles/wimaxasncp.dir/plugin.c.s

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/flags.make
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o: plugins/epan/wimaxasncp/packet-wimaxasncp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o   -c /opt/wireshark/plugins/epan/wimaxasncp/packet-wimaxasncp.c

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.i"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/epan/wimaxasncp/packet-wimaxasncp.c > CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.i

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.s"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/epan/wimaxasncp/packet-wimaxasncp.c -o CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.s

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/flags.make
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o: plugins/epan/wimaxasncp/wimaxasncp_dict.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o   -c /opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict.c

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.i"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict.c > CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.i

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.s"
	cd /opt/wireshark/plugins/epan/wimaxasncp && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/epan/wimaxasncp/wimaxasncp_dict.c -o CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.s

# Object files for target wimaxasncp
wimaxasncp_OBJECTS = \
"CMakeFiles/wimaxasncp.dir/plugin.c.o" \
"CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o" \
"CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o"

# External object files for target wimaxasncp
wimaxasncp_EXTERNAL_OBJECTS =

run/plugins/4.0/epan/wimaxasncp.so: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/plugin.c.o
run/plugins/4.0/epan/wimaxasncp.so: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/packet-wimaxasncp.c.o
run/plugins/4.0/epan/wimaxasncp.so: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/wimaxasncp_dict.c.o
run/plugins/4.0/epan/wimaxasncp.so: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/build.make
run/plugins/4.0/epan/wimaxasncp.so: run/libwireshark.so.16.0.2
run/plugins/4.0/epan/wimaxasncp.so: run/libwiretap.so.13.0.2
run/plugins/4.0/epan/wimaxasncp.so: run/libwsutil.so.14.0.0
run/plugins/4.0/epan/wimaxasncp.so: /usr/lib/aarch64-linux-gnu/libgmodule-2.0.so
run/plugins/4.0/epan/wimaxasncp.so: /usr/lib/aarch64-linux-gnu/libglib-2.0.so
run/plugins/4.0/epan/wimaxasncp.so: plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C shared module ../../../run/plugins/4.0/epan/wimaxasncp.so"
	cd /opt/wireshark/plugins/epan/wimaxasncp && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wimaxasncp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/build: run/plugins/4.0/epan/wimaxasncp.so

.PHONY : plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/build

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/clean:
	cd /opt/wireshark/plugins/epan/wimaxasncp && $(CMAKE_COMMAND) -P CMakeFiles/wimaxasncp.dir/cmake_clean.cmake
.PHONY : plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/clean

plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/depend: plugins/epan/wimaxasncp/plugin.c
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/depend: plugins/epan/wimaxasncp/wimaxasncp_dict.c
plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/depend: plugins/epan/wimaxasncp/wimaxasncp_dict_lex.h
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/plugins/epan/wimaxasncp /opt/wireshark /opt/wireshark/plugins/epan/wimaxasncp /opt/wireshark/plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : plugins/epan/wimaxasncp/CMakeFiles/wimaxasncp.dir/depend

