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

# Utility rule file for checkAPI_mate.

# Include the progress variables for this target.
include plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/progress.make

plugins/epan/mate/CMakeFiles/checkAPI_mate:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Running checkAPI_mate"
	cd /opt/wireshark/plugins/epan/mate && /usr/bin/perl /opt/wireshark/tools/checkAPIs.pl --group dissectors-prohibited --group dissectors-restricted packet-mate.c mate_setup.c mate_runtime.c mate_util.c mate.h mate_util.h /opt/wireshark/plugins/epan/mate/mate_grammar.lemon

checkAPI_mate: plugins/epan/mate/CMakeFiles/checkAPI_mate
checkAPI_mate: plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/build.make

.PHONY : checkAPI_mate

# Rule to build all files generated by this target.
plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/build: checkAPI_mate

.PHONY : plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/build

plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/clean:
	cd /opt/wireshark/plugins/epan/mate && $(CMAKE_COMMAND) -P CMakeFiles/checkAPI_mate.dir/cmake_clean.cmake
.PHONY : plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/clean

plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/plugins/epan/mate /opt/wireshark /opt/wireshark/plugins/epan/mate /opt/wireshark/plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : plugins/epan/mate/CMakeFiles/checkAPI_mate.dir/depend

