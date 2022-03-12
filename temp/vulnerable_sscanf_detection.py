# This is a simple script to detect vulnerability introduced by a unsanitized sscanf.
# The idea can be traced back to this article. https://www.zerodayinitiative.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code
# @category: CEG7420.Demo
# @author: Junjie Zhang

from ghidra.program.model.pcode import *
from ghidra.app.decompiler import *
from ghidra.program.model.symbol import SymbolUtilities

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
    print("---------------")
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
        while pcode_seq.hasNext():
            op = pcode_seq.next()
            print("Example: " + op.toString())
            if op.getOpcode() == PcodeOp.CALL:
                #print(op.toString())
                output = op.getOutput()
                inputs = op.getInputs()
                input0 = inputs[0]
                if input0.getOffset() == sym.getAddress().getOffset():
                    isVulnerable = True
                    if output is None:
                        isVulnerable = True
                        #print("Warning: @" + op.getSeqnum().getTarget().toString() + " " + op.toString())
                    else:
                        #print("More Analysis: @" + op.getSeqnum().getTarget().toString() + " " + op.toString())
                        descendants = output.getDescendants()
                        
                        for d in descendants:
                            if d.getOpcode() == PcodeOp.INT_EQUAL:
                                isVulnerable = False
                                break
                    
                    if isVulnerable:
                        print("Possible Vulnerability @" + op.getSeqnum().getTarget().toString() + " " + op.toString())





#inst_iter = plist.getInstructions(func.getBody(), True)

program = currentProgram
plist = program.getListing()
symbolTable = program.getSymbolTable()
allSymbols = symbolTable.getAllSymbols(False)


symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "main", None)

if symbol != None:
    print("Found: " + symbol.getName() + " " + symbol.getSymbolType().toString())
else:
    print("DID NOT FIND ANYTHING HERE")

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
