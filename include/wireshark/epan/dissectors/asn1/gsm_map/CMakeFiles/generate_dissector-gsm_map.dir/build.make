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

# Utility rule file for generate_dissector-gsm_map.

# Include the progress variables for this target.
include epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/progress.make

epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map: epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp


epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: tools/asn2wrs.py
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MobileDomainDefinitions.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-ApplicationContexts.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-SS-Code.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-BS-Code.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-TS-Code.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-ExtensionDataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-CommonDataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-SS-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-ER-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-SM-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-OM-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-MS-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-CH-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-LCS-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-GR-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-DialogueInformation.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-LocationServiceOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-Group-Call-Operations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-ShortMessageServiceOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-SupplementaryServiceOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-CallHandlingOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-OperationAndMaintenanceOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-MobileServiceOperations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-Errors.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/MAP-Protocol.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/GSMMAP.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/SS-DataTypes.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/SS-Operations.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/Ericsson.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/Nokia.asn
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/packet-gsm_map-template.c
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/packet-gsm_map-template.h
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/gsm_map.cnf
epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp: epan/dissectors/asn1/gsm_map/../ros/Remote-Operations-Information-Objects.asn
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/opt/wireshark/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating packet-gsm_map-stamp"
	cd /opt/wireshark/epan/dissectors/asn1/gsm_map && /usr/bin/python3 /opt/wireshark/tools/asn2wrs.py -b -c /opt/wireshark/epan/dissectors/asn1/gsm_map/gsm_map.cnf -s /opt/wireshark/epan/dissectors/asn1/gsm_map/packet-gsm_map-template -D /opt/wireshark/epan/dissectors/asn1/gsm_map -O /opt/wireshark/epan/dissectors ../ros/Remote-Operations-Information-Objects.asn MobileDomainDefinitions.asn MAP-ApplicationContexts.asn MAP-SS-Code.asn MAP-BS-Code.asn MAP-TS-Code.asn MAP-ExtensionDataTypes.asn MAP-CommonDataTypes.asn MAP-SS-DataTypes.asn MAP-ER-DataTypes.asn MAP-SM-DataTypes.asn MAP-OM-DataTypes.asn MAP-MS-DataTypes.asn MAP-CH-DataTypes.asn MAP-LCS-DataTypes.asn MAP-GR-DataTypes.asn MAP-DialogueInformation.asn MAP-LocationServiceOperations.asn MAP-Group-Call-Operations.asn MAP-ShortMessageServiceOperations.asn MAP-SupplementaryServiceOperations.asn MAP-CallHandlingOperations.asn MAP-OperationAndMaintenanceOperations.asn MAP-MobileServiceOperations.asn MAP-Errors.asn MAP-Protocol.asn GSMMAP.asn SS-DataTypes.asn SS-Operations.asn Ericsson.asn Nokia.asn
	cd /opt/wireshark/epan/dissectors/asn1/gsm_map && /usr/bin/python3 -c "import shutil, sys; x,s,d=sys.argv; open(d, 'w'); shutil.copystat(s, d)" /opt/wireshark/epan/dissectors/packet-gsm_map.c packet-gsm_map-stamp

generate_dissector-gsm_map: epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map
generate_dissector-gsm_map: epan/dissectors/asn1/gsm_map/packet-gsm_map-stamp
generate_dissector-gsm_map: epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/build.make

.PHONY : generate_dissector-gsm_map

# Rule to build all files generated by this target.
epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/build: generate_dissector-gsm_map

.PHONY : epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/build

epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/clean:
	cd /opt/wireshark/epan/dissectors/asn1/gsm_map && $(CMAKE_COMMAND) -P CMakeFiles/generate_dissector-gsm_map.dir/cmake_clean.cmake
.PHONY : epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/clean

epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/depend:
	cd /opt/wireshark && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/wireshark /opt/wireshark/epan/dissectors/asn1/gsm_map /opt/wireshark /opt/wireshark/epan/dissectors/asn1/gsm_map /opt/wireshark/epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : epan/dissectors/asn1/gsm_map/CMakeFiles/generate_dissector-gsm_map.dir/depend

