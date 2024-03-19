# This is a simple script to dump the refined pcode.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

#from ghidra.app.decompiler import *
#from ghidra.app.script.GhidraScript import *
from ghidra.program.model.block import BasicBlockModel

#plist = currentProgram.getListing()
func = getFunctionContaining(currentAddress)
blockModel = BasicBlockModel(currentProgram)

if func is None:
    print("No function is found at this address")
elif blockModel is None:
    print("No basic block model is generated for this function")
else:
    print("Enumerate basic blocks")
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
    for block in blocks:
        startAddress = block.getMinAddress()
        endAddress = block.getMaxAddress()
        print("Basic Block: {} - {}".format(startAddress.toString(), endAddress.toString()))

    
