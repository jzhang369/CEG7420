#Use gcc to generate the binary file from the source code
gcc -O0 -no-pie -o prog64 main.c sum.c
gcc -m32 -O0 -no-pie -o prog32 main.c sum.c

#no-pie will make sure the gcc generates executable rather than a shared library for ALSR. 

