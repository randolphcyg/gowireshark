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

# Utility rule file for generate_dissector-pkixqualified.

# Include the progress variables for this target.
include epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/progress.make

epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified: epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp


epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: tools/asn2wrs.py
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/PKIXqualified.asn
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/PKIXServiceNameSAN88.asn
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/PKIXServiceNameSAN93.asn
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/packet-pkixqualified-template.c
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/packet-pkixqualified-template.h
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/pkixqualified/pkixqualified.cnf
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/x509af/x509af-exp.cnf
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/x509ce/x509ce-exp.cnf
epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp: epan/dissectors/asn1/x509sat/x509sat-exp.cnf
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating packet-pkixqualified-stamp"
	cd /opt/wireshark/epan/dissectors/asn1/pkixqualified && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -b -p pkixqualified -c /opt/wireshark/epan/dissectors/asn1/pkixqualified/pkixqualified.cnf -s /opt/wireshark/epan/dissectors/asn1/pkixqualified/packet-pkixqualified-template -D /opt/wireshark/epan/dissectors/asn1/pkixqualified -O /opt/wireshark/epan/dissectors PKIXqualified.asn PKIXServiceNameSAN88.asn PKIXServiceNameSAN93.asn
	cd /opt/wireshark/epan/dissectors/asn1/pkixqualified && /usr/bin/python3 -c "import shutil, sys; x,s,d=sys.argv; open(d, 'w'); shutil.copystat(s, d)" /opt/wireshark/epan/dissectors/packet-pkixqualified.c packet-pkixqualified-stamp

generate_dissector-pkixqualified: epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified
generate_dissector-pkixqualified: epan/dissectors/asn1/pkixqualified/packet-pkixqualified-stamp
generate_dissector-pkixqualified: epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/build.make

.PHONY : generate_dissector-pkixqualified

# Rule to build all files generated by this target.
epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/build: generate_dissector-pkixqualified

.PHONY : epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/build

epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/pkixqualified && $(CMAKE_COMMAND) -P CMakeFiles/generate_dissector-pkixqualified.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/clean

epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/pkixqualified /opt/wireshark /opt/wireshark/epan/dissectors/asn1/pkixqualified /opt/wireshark/epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/pkixqualified/CMakeFiles/generate_dissector-pkixqualified.dir/depend

