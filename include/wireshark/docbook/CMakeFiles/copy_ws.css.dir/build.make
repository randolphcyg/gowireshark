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

# Utility rule file for copy_ws.css.

# Include the progress variables for this target.
include docbook/CMakeFiles/copy_ws.css.dir/progress.make

copy_ws.css: docbook/CMakeFiles/copy_ws.css.dir/build.make

.PHONY : copy_ws.css

# Rule to build all files generated by this target.
docbook/CMakeFiles/copy_ws.css.dir/build: copy_ws.css

.PHONY : docbook/CMakeFiles/copy_ws.css.dir/build

docbook/CMakeFiles/copy_ws.css.dir/clean:
	cd /opt/wireshark/docbook && $(CMAKE_COMMAND) -P CMakeFiles/copy_ws.css.dir/cmake_clean.cmake
.PHONY : docbook/CMakeFiles/copy_ws.css.dir/clean

docbook/CMakeFiles/copy_ws.css.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/docbook /opt/wireshark /opt/wireshark/docbook /opt/wireshark/docbook/CMakeFiles/copy_ws.css.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : docbook/CMakeFiles/copy_ws.css.dir/depend

