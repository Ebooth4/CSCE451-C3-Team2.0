# CSCE 451 Challenge 3: Team 2.0

Ghidra script for Challenge 3

Team members:

- Evan Graham
- Joshua Wood
- Xiaohu Huang
- Michael Mirhosseini

## Introduction
For challenge 3 we created a scirpt with both Ghidrathon and Jep in order to break down the reversed code into a more readable graph. This allows us to follow function calls and see how often certain functions and variables are used. It also shows recursion and makes it easy to eliminate dummy information from the program.

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
