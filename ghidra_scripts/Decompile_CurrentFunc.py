# This is a simple script to decompile a function
# @category: CEG7420.Demo
# @author: Junjie Zhang

from ghidra.app.decompiler import DecompInterface


func = getFunctionContaining(currentAddress)
myDecomp = DecompInterface()
myDecomp.openProgram(currentProgram)

results = myDecomp.decompileFunction(func, 60, monitor)
ccode = results.getDecompiledFunction().getC()

if ccode is not None: 
    print(ccode)
else:
    print("Failed to decompile the code into C.")

