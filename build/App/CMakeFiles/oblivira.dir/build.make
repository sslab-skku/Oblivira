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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/hojoon/copy_test_app

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/hojoon/copy_test_app/build

# Include any dependencies generated for this target.
include App/CMakeFiles/oblivira.dir/depend.make

# Include the progress variables for this target.
include App/CMakeFiles/oblivira.dir/progress.make

# Include the compile flags for this target's objects.
include App/CMakeFiles/oblivira.dir/flags.make

App/CMakeFiles/oblivira.dir/TestApp.cpp.o: App/CMakeFiles/oblivira.dir/flags.make
App/CMakeFiles/oblivira.dir/TestApp.cpp.o: ../App/TestApp.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/hojoon/copy_test_app/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object App/CMakeFiles/oblivira.dir/TestApp.cpp.o"
	cd /home/hojoon/copy_test_app/build/App && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/oblivira.dir/TestApp.cpp.o -c /home/hojoon/copy_test_app/App/TestApp.cpp

App/CMakeFiles/oblivira.dir/TestApp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/oblivira.dir/TestApp.cpp.i"
	cd /home/hojoon/copy_test_app/build/App && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/hojoon/copy_test_app/App/TestApp.cpp > CMakeFiles/oblivira.dir/TestApp.cpp.i

App/CMakeFiles/oblivira.dir/TestApp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/oblivira.dir/TestApp.cpp.s"
	cd /home/hojoon/copy_test_app/build/App && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/hojoon/copy_test_app/App/TestApp.cpp -o CMakeFiles/oblivira.dir/TestApp.cpp.s

# Object files for target oblivira
oblivira_OBJECTS = \
"CMakeFiles/oblivira.dir/TestApp.cpp.o"

# External object files for target oblivira
oblivira_EXTERNAL_OBJECTS =

oblivira: App/CMakeFiles/oblivira.dir/TestApp.cpp.o
oblivira: App/CMakeFiles/oblivira.dir/build.make
oblivira: App/CMakeFiles/oblivira.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/hojoon/copy_test_app/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../oblivira"
	cd /home/hojoon/copy_test_app/build/App && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/oblivira.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
App/CMakeFiles/oblivira.dir/build: oblivira

.PHONY : App/CMakeFiles/oblivira.dir/build

App/CMakeFiles/oblivira.dir/clean:
	cd /home/hojoon/copy_test_app/build/App && $(CMAKE_COMMAND) -P CMakeFiles/oblivira.dir/cmake_clean.cmake
.PHONY : App/CMakeFiles/oblivira.dir/clean

App/CMakeFiles/oblivira.dir/depend:
	cd /home/hojoon/copy_test_app/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/hojoon/copy_test_app /home/hojoon/copy_test_app/App /home/hojoon/copy_test_app/build /home/hojoon/copy_test_app/build/App /home/hojoon/copy_test_app/build/App/CMakeFiles/oblivira.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : App/CMakeFiles/oblivira.dir/depend

