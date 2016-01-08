File: README.txt
Project 3:	Distance Vector
Name: Saurav Maheshwary (samahesh@umail.iu.edu)
Date: 30 November 2015

=================================================== PROVIDED FILES =======================================================
1. node.c - Contains the code for the node
2. makefile - Used for compiling and building the application
3. README.txt - this file
4. projectReport.pdf - Details how the project has been implemented
5. sampleFiles - directory contains the config files for a 18 node network described in the writeup

=================================================== HOW TO COMPILE =======================================================
$ make all

=================================================== HOW TO RUN ===========================================================
$ ./node <configFile> <portNumber> <timeToLive> <infinity> <period> <splitHorizon>


1. configFile contains the entries for all the nodes in the network other than itself.
   It helps the node determine what all nodes are its neighbors. I have accepted hostnames (not IP Addresses) as entries.
   Example Entry:
	silo.soic.indiana.edu<space>yes<newLine>
2. portNumber is an integer; and is the same for all the nodes.
3. timeToLive is an integer.
4. infinity is an integer.
5. period is an integer.
6. splitHorizon is an integer. If it is to be enabled enter 1 otherwise enter 0.
7. For usage help on the console, enter the following command:
	$ ./node --help

==========================================================================================================================