# This is a simple script to detect vulnerability introduced by a unsanitized sscanf.
# The idea can be traced back to this article. https://www.zerodayinitiative.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code
# @category: CEG7420.Demo
# @author: Junjie Zhang

from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import *

def analyze(plist, func, instAddr):
    inst = plist.getInstructionAt(instAddr)
    pcode_seq = inst.getPcode()
    print("@" + instAddr.toString() + ":")
    for op in pcode_seq: 
        if op.getOpcode() == PcodeOp.CALL:
            print(op.toString())
            output = op.getOutput()
            if output is None:
                print("The output is none")


def analyze2(program, func, sym):
    print("I am here for " + sym.getAddress().toString())
    decomp = DecompInterface()
    decomp.openProgram(program)
    decomp_results = decomp.decompileFunction(func, 30, None)

    if decomp_results is None:
        print("decomp result is none here")

    results_highFunction = decomp_results.getHighFunction()

    if results_highFunction is None:
        print("highFunction is none here")
    else:
        pcode_seq = results_highFunction.getPcodeOps()
        for op in pcode_seq:
            if op.opcode == PcodeOp.CALL:
                print(op.toString())



#inst_iter = plist.getInstructions(func.getBody(), True)

program = currentProgram
plist = program.getListing()
symbolTable = program.getSymbolTable()
allSymbols = symbolTable.getAllSymbols(False)

while allSymbols.hasNext():
    sym = allSymbols.next()
    sym_name_str = sym.getName()
    sym_type_str = sym.getSymbolType().toString()
    sym_address_str = sym.getAddress().toString()

    #if "sscanf" in sym_name_str:
    #print(sym_name_str + " : " + sym_type_str + ":" + sym_address_str); 

    if "sscanf" in sym_name_str and sym_type_str == "Function": 
        #print(sym.getName() + " : " + sym.getSymbolType().toString()) 
        refs = sym.getReferences()
        for r in refs:
            if r.getReferenceType().isCall() and r.getFromAddress() is not None:
                f = getFunctionContaining(r.getFromAddress()); 
                if not f.isThunk():
                    #Now this is the immeidate caller of sscanf that is of our interest
                    #print(sym.getName() + "@" + sym_address_str + " ref-from the function@" + f.getEntryPoint().toString() + " with name:  " + f.getName() + " isThunk? " + str(f.isThunk()))
                    #analyze(plist, f, r.getFromAddress())
                    print(sym.getName() + "@" + sym_address_str + " or @" + hex(sym.getAddress().getOffset()) + " ref-from the function@" + f.getEntryPoint().toString() + " with name:  " + f.getName())
                    analyze2(program, f, sym)
