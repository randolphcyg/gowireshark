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

# Utility rule file for generate-p22-exp.cnf.

# Include the progress variables for this target.
include epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/progress.make

epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf: epan/dissectors/asn1/p22/p22-exp.cnf


epan/dissectors/asn1/p22/p22-exp.cnf: tools/asn2wrs.py
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSInformationObjects.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSHeadingExtensions.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSExtendedBodyPartTypes2.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSFileTransferBodyPartType.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSExtendedVoiceBodyPartType.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSForwardedContentBodyPartType.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSMessageStoreAttributes.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSSecurityExtensions.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSObjectIdentifiers.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/IPMSUpperBounds.asn
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/packet-p22-template.c
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/packet-p22-template.h
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p22/p22.cnf
epan/dissectors/asn1/p22/p22-exp.cnf: epan/dissectors/asn1/p1/p1-exp.cnf
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating p22-exp.cnf"
	cd /opt/wireshark/epan/dissectors/asn1/p22 && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -E -b -C -p p22 -c /opt/wireshark/epan/dissectors/asn1/p22/p22.cnf -D /opt/wireshark/epan/dissectors/asn1/p22 IPMSInformationObjects.asn IPMSHeadingExtensions.asn IPMSExtendedBodyPartTypes2.asn IPMSFileTransferBodyPartType.asn IPMSExtendedVoiceBodyPartType.asn IPMSForwardedContentBodyPartType.asn IPMSMessageStoreAttributes.asn IPMSSecurityExtensions.asn IPMSObjectIdentifiers.asn IPMSUpperBounds.asn

generate-p22-exp.cnf: epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf
generate-p22-exp.cnf: epan/dissectors/asn1/p22/p22-exp.cnf
generate-p22-exp.cnf: epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/build.make

.PHONY : generate-p22-exp.cnf

# Rule to build all files generated by this target.
epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/build: generate-p22-exp.cnf

.PHONY : epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/build

epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/p22 && $(CMAKE_COMMAND) -P CMakeFiles/generate-p22-exp.cnf.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/clean

epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/p22 /opt/wireshark /opt/wireshark/epan/dissectors/asn1/p22 /opt/wireshark/epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/p22/CMakeFiles/generate-p22-exp.cnf.dir/depend

