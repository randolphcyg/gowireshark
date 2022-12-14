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
include plugins/epan/gryphon/CMakeFiles/gryphon.dir/depend.make

# Include the progress variables for this target.
include plugins/epan/gryphon/CMakeFiles/gryphon.dir/progress.make

# Include the compile flags for this target's objects.
include plugins/epan/gryphon/CMakeFiles/gryphon.dir/flags.make

plugins/epan/gryphon/plugin.c: plugins/epan/gryphon/packet-gryphon.c
plugins/epan/gryphon/plugin.c: tools/make-plugin-reg.py
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating plugins/epan/gryphon/plugin.c"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/python3 /opt/wireshark/tools/make-plugin-reg.py /opt/wireshark/plugins/epan/gryphon plugin packet-gryphon.c

plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.o: plugins/epan/gryphon/CMakeFiles/gryphon.dir/flags.make
plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.o: plugins/epan/gryphon/plugin.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.o"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/gryphon.dir/plugin.c.o   -c /opt/wireshark/plugins/epan/gryphon/plugin.c

plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/gryphon.dir/plugin.c.i"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/epan/gryphon/plugin.c > CMakeFiles/gryphon.dir/plugin.c.i

plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/gryphon.dir/plugin.c.s"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/epan/gryphon/plugin.c -o CMakeFiles/gryphon.dir/plugin.c.s

plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.o: plugins/epan/gryphon/CMakeFiles/gryphon.dir/flags.make
plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.o: plugins/epan/gryphon/packet-gryphon.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.o"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/gryphon.dir/packet-gryphon.c.o   -c /opt/wireshark/plugins/epan/gryphon/packet-gryphon.c

plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/gryphon.dir/packet-gryphon.c.i"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/epan/gryphon/packet-gryphon.c > CMakeFiles/gryphon.dir/packet-gryphon.c.i

plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/gryphon.dir/packet-gryphon.c.s"
	cd /opt/wireshark/plugins/epan/gryphon && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/epan/gryphon/packet-gryphon.c -o CMakeFiles/gryphon.dir/packet-gryphon.c.s

# Object files for target gryphon
gryphon_OBJECTS = \
"CMakeFiles/gryphon.dir/plugin.c.o" \
"CMakeFiles/gryphon.dir/packet-gryphon.c.o"

# External object files for target gryphon
gryphon_EXTERNAL_OBJECTS =

run/plugins/4.0/epan/gryphon.so: plugins/epan/gryphon/CMakeFiles/gryphon.dir/plugin.c.o
run/plugins/4.0/epan/gryphon.so: plugins/epan/gryphon/CMakeFiles/gryphon.dir/packet-gryphon.c.o
run/plugins/4.0/epan/gryphon.so: plugins/epan/gryphon/CMakeFiles/gryphon.dir/build.make
run/plugins/4.0/epan/gryphon.so: run/libwireshark.so.16.0.2
run/plugins/4.0/epan/gryphon.so: run/libwiretap.so.13.0.2
run/plugins/4.0/epan/gryphon.so: run/libwsutil.so.14.0.0
run/plugins/4.0/epan/gryphon.so: /usr/lib/aarch64-linux-gnu/libgmodule-2.0.so
run/plugins/4.0/epan/gryphon.so: /usr/lib/aarch64-linux-gnu/libglib-2.0.so
run/plugins/4.0/epan/gryphon.so: plugins/epan/gryphon/CMakeFiles/gryphon.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C shared module ../../../run/plugins/4.0/epan/gryphon.so"
	cd /opt/wireshark/plugins/epan/gryphon && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gryphon.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
plugins/epan/gryphon/CMakeFiles/gryphon.dir/build: run/plugins/4.0/epan/gryphon.so

.PHONY : plugins/epan/gryphon/CMakeFiles/gryphon.dir/build

plugins/epan/gryphon/CMakeFiles/gryphon.dir/clean:
	cd /opt/wireshark/plugins/epan/gryphon && $(CMAKE_COMMAND) -P CMakeFiles/gryphon.dir/cmake_clean.cmake
.PHONY : plugins/epan/gryphon/CMakeFiles/gryphon.dir/clean

plugins/epan/gryphon/CMakeFiles/gryphon.dir/depend: plugins/epan/gryphon/plugin.c
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/plugins/epan/gryphon /opt/wireshark /opt/wireshark/plugins/epan/gryphon /opt/wireshark/plugins/epan/gryphon/CMakeFiles/gryphon.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : plugins/epan/gryphon/CMakeFiles/gryphon.dir/depend

