# CSCE 451 Challenge 3: Team 2.0

Ghidra script for Challenge 3

Team members:

- Evan Graham
- Joshua Wood
- Xiaohu Huang
- Michael Mirhosseini

## Introduction

For challenge 3 we created a script with both Ghidrathon and Jep in order to break down the reversed code into a more readable graph. This allows us to follow function calls and see how often certain functions and variables are used. It also shows recursion and makes it easy to eliminate dummy information from the program.

## Purpose of Our Script

The purpose of C3 is to iterate and build upon the groundwork set by Ghidra in our own innovative way. Throughout the journey to reverse engineer various projects within this class, we were met with roadblocks purposely made to set us astray, with false functions, variables, and even simply confusing variables or statements. Furthermore, in a challenge like the previously assigned CrackMe, various objects including functions, variables, and structs were falsified and obfuscated with the sole purpose of being misleading.Because reverse engineering is a complex process and the slightest errors can lead to an incorrect path, we aim to alleviate this problem as well as make the reversing process easier to process.

As we have learned there is no way to completely and comprehensively solve this problem, as otherwise reverse engineering would be a trivial matter all by itself. However, it is possible to make the reversed code easier to go through and absorb, this is what we would like to accomplish. We will accomplish this by creating a script for Ghidra which makes dummy variables and functions easier to identify and eliminate. Furthermore, as humans are visual learners, we would like to make a graphical representation of the functions and variables and see what they call, where they lead to, and how often they are used. We believe that by overcoming these two challenges, it will greatly aid us in all forms of reverse engineering in the future.

## Installation Instructions:

This script makes use of the `networkx` python package, which requires a working python3 interpreter. However, Ghidra does not have a built-in python3 interpreter, so an extension is needed to allow our script to run.

To install the `networkx` package, make sure your python interpreter is up-to-date and run the following command in your terminal:

```
python -m pip install networkx
```

There are multiple options for python3 interpreters, but the one that we used is called Ghidrathon. To install this extension, follow the instructions laid out in Ghidrathon's repository at [https://github.com/mandiant/Ghidrathon](https://github.com/mandiant/Ghidrathon).

Once you have Ghidrathon installed, restart Ghidra and open the Script Manager window. Create a new script and make sure to select "Python 3" as the script type. Once the new script is open, simply copy and paste the code from our script into the text editor before saving and running the script.

## Testing Instructions

### With Ghidrathon:

- Get the NetworkX python library using the command ‘pip install networkx’.
- Install Ghidrathon using the instructions at https://github.com/mandiant/Ghidrathon
- Unzip the file c3-t2-0.zip and analyze one of the .exe files that we provided using Ghidra (or create your own for testing).
- Open the script manager, create a new script (selecting the Python 3 interpreter), and paste in the code from ‘GraphFunctionAndVariableCalls.py’.
- Run the script. Click the save button on each graph to save an image for future reference. Note: there may be a bug with Ghidrathon that causes Ghidra to crash if you try to run the script more than once. This can be solved by resolving Jep dependencies with numpy, but the crashing has nothing to do with our script.

### Without Ghidrathon (note: the script is not intended to be run this way, so there is some inconvenience to the user in copying and pasting here):

- Get the NetworkX python library using the command ‘pip install networkx’.
- Unzip the file c3-t2-0.zip and analyze one of the .exe files that we provided using Ghidra (or create your own for testing).
- Open the script manager, create a new script (selecting the Python 3 interpreter), and paste in the code from ‘CreateDependencies.py’.
- Run the Ghidra script and copy the output. Open the script ‘GraphDependencies.py’ and paste the output into the list variable at the beginning before running.

## Challenge 4 Changes

Here is an extensive list of improvements we made in Challenge 4:

- Scope Expansion. The initial code that we wrote only worked for a small scope of binaries. This was due to various edge cases that were not accounted for in the first implementation of the code. In C4, we took a lot more of these edge cases into account and wrote checks in the code to allow for a much more broad scope of binaries that can be reversed.
- Readability improvements: improved graphing function to make the graphs more readable for the users. This included updates to the node size, text wrap, and seed for the graph to reduce overlap.
- Added functionality to recognize and display branching conditional statements as an additional graph.
- Removes some built-in C++ functions: some C++ functions such as cout and endl were called and not defined in the executable. Our code made a list of these functions so that the function search algorithm could recognize and skip over these functions.
- Added a demangler to clean up function names and make it clear which functions are built-in. When a compiler creates the executable for code, it runs an algorithm called "mangling" to ensure that no two variables or functions are named exactly the same way. Our goal in writing the demangler was to reverse this process to make the graphs more readable for the user. The demangler uses two different methods in tandem to clean up these names:
  1.  The function calls a ghidra object called DemanglerCmd to see if it can use what it knows about the compiler to reverse the mangling algorithm.
  2.  The function uses regular expressions to filter out commonly used phrases in the mangling algorithm.
