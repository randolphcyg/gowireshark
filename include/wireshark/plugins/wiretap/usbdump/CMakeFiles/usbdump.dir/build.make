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
include plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/depend.make

# Include the progress variables for this target.
include plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/progress.make

# Include the compile flags for this target's objects.
include plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/flags.make

plugins/wiretap/usbdump/plugin.c: plugins/wiretap/usbdump/usbdump.c
plugins/wiretap/usbdump/plugin.c: tools/make-plugin-reg.py
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating plugins/wiretap/usbdump/plugin.c"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/python3 /opt/wireshark/tools/make-plugin-reg.py /opt/wireshark/plugins/wiretap/usbdump plugin_wtap usbdump.c

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.o: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/flags.make
plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.o: plugins/wiretap/usbdump/plugin.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.o"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/usbdump.dir/plugin.c.o   -c /opt/wireshark/plugins/wiretap/usbdump/plugin.c

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/usbdump.dir/plugin.c.i"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/wiretap/usbdump/plugin.c > CMakeFiles/usbdump.dir/plugin.c.i

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/usbdump.dir/plugin.c.s"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/wiretap/usbdump/plugin.c -o CMakeFiles/usbdump.dir/plugin.c.s

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.o: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/flags.make
plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.o: plugins/wiretap/usbdump/usbdump.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.o"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/usbdump.dir/usbdump.c.o   -c /opt/wireshark/plugins/wiretap/usbdump/usbdump.c

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/usbdump.dir/usbdump.c.i"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /opt/wireshark/plugins/wiretap/usbdump/usbdump.c > CMakeFiles/usbdump.dir/usbdump.c.i

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/usbdump.dir/usbdump.c.s"
	cd /opt/wireshark/plugins/wiretap/usbdump && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /opt/wireshark/plugins/wiretap/usbdump/usbdump.c -o CMakeFiles/usbdump.dir/usbdump.c.s

# Object files for target usbdump
usbdump_OBJECTS = \
"CMakeFiles/usbdump.dir/plugin.c.o" \
"CMakeFiles/usbdump.dir/usbdump.c.o"

# External object files for target usbdump
usbdump_EXTERNAL_OBJECTS =

run/plugins/4.0/wiretap/usbdump.so: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/plugin.c.o
run/plugins/4.0/wiretap/usbdump.so: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/usbdump.c.o
run/plugins/4.0/wiretap/usbdump.so: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/build.make
run/plugins/4.0/wiretap/usbdump.so: run/libwiretap.so.13.0.2
run/plugins/4.0/wiretap/usbdump.so: run/libwsutil.so.14.0.0
run/plugins/4.0/wiretap/usbdump.so: /usr/lib/aarch64-linux-gnu/libglib-2.0.so
run/plugins/4.0/wiretap/usbdump.so: /usr/lib/aarch64-linux-gnu/libgmodule-2.0.so
run/plugins/4.0/wiretap/usbdump.so: plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C shared module ../../../run/plugins/4.0/wiretap/usbdump.so"
	cd /opt/wireshark/plugins/wiretap/usbdump && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/usbdump.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/build: run/plugins/4.0/wiretap/usbdump.so

.PHONY : plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/build

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/clean:
	cd /opt/wireshark/plugins/wiretap/usbdump && $(CMAKE_COMMAND) -P CMakeFiles/usbdump.dir/cmake_clean.cmake
.PHONY : plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/clean

plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/depend: plugins/wiretap/usbdump/plugin.c
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/plugins/wiretap/usbdump /opt/wireshark /opt/wireshark/plugins/wiretap/usbdump /opt/wireshark/plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : plugins/wiretap/usbdump/CMakeFiles/usbdump.dir/depend

