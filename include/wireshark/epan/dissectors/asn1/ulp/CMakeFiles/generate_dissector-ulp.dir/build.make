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

# Utility rule file for generate_dissector-ulp.

# Include the progress variables for this target.
include epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/progress.make

epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp: epan/dissectors/asn1/ulp/packet-ulp-stamp


epan/dissectors/asn1/ulp/packet-ulp-stamp: tools/asn2wrs.py
epan/dissectors/asn1/ulp/packet-ulp-stamp: epan/dissectors/asn1/ulp/ULP.asn
epan/dissectors/asn1/ulp/packet-ulp-stamp: epan/dissectors/asn1/ulp/SUPL.asn
epan/dissectors/asn1/ulp/packet-ulp-stamp: epan/dissectors/asn1/ulp/ULP-Components.asn
epan/dissectors/asn1/ulp/packet-ulp-stamp: epan/dissectors/asn1/ulp/packet-ulp-template.c
epan/dissectors/asn1/ulp/packet-ulp-stamp: epan/dissectors/asn1/ulp/ulp.cnf
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating packet-ulp-stamp"
	cd /opt/wireshark/epan/dissectors/asn1/ulp && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -p ulp -c /opt/wireshark/epan/dissectors/asn1/ulp/ulp.cnf -s /opt/wireshark/epan/dissectors/asn1/ulp/packet-ulp-template -D /opt/wireshark/epan/dissectors/asn1/ulp -O /opt/wireshark/epan/dissectors ULP.asn SUPL.asn ULP-Components.asn
	cd /opt/wireshark/epan/dissectors/asn1/ulp && /usr/bin/python3 -c "import shutil, sys; x,s,d=sys.argv; open(d, 'w'); shutil.copystat(s, d)" /opt/wireshark/epan/dissectors/packet-ulp.c packet-ulp-stamp

generate_dissector-ulp: epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp
generate_dissector-ulp: epan/dissectors/asn1/ulp/packet-ulp-stamp
generate_dissector-ulp: epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/build.make

.PHONY : generate_dissector-ulp

# Rule to build all files generated by this target.
epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/build: generate_dissector-ulp

.PHONY : epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/build

epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/ulp && $(CMAKE_COMMAND) -P CMakeFiles/generate_dissector-ulp.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/clean

epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/ulp /opt/wireshark /opt/wireshark/epan/dissectors/asn1/ulp /opt/wireshark/epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/ulp/CMakeFiles/generate_dissector-ulp.dir/depend

