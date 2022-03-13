# This is a simple script to detect vulnerability introduced by a unsanitized sscanf.
# The idea can be traced back to this article. https://www.zerodayinitiative.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code
# @category: CEG7420.Demo
# @author: Junjie Zhang

import re
from ghidra.program.model.pcode import *
from ghidra.app.decompiler import *
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.symbol import SymbolType


def getSymbols(program, regexr):
#Given a programDB and a regular expression, return all symbols whose names match with the given regexr
    symbolTable = program.getSymbolTable()
    allSymbols = symbolTable.getAllSymbols(False)
    results = filter(lambda symbol: re.search(regexr, symbol.getName()), allSymbols)
    return results
        


def analyze(decomp, func, symbols):
    print("---------------")
 
    decomp_results = decomp.decompileFunction(func, 30, None)
    if decomp_results is None:
        return None

    results_highFunction = decomp_results.getHighFunction()
    if results_highFunction is None:
        return None

    symbols_offsets = set(s.getAddress().getOffset() for s in symbols)
    pcode_seq = results_highFunction.getPcodeOps() 
    pcode_calls = filter(lambda p: p.getOpcode() == PcodeOp.CALL and p.getInputs()[0].getOffset() in symbols_offsets,  pcode_seq)

    vulResults = set()

    for op in pcode_calls:
        #print(op.getSeqnum().getTarget().toString() + " " + op.toString())
        if op.getOutput() is None:
            vulResults.add(op.getSeqnum().getTarget())
            print("Warning: a possible vulnerability @" + op.getSeqnum().getTarget().toString() + " since the output of sscanf is not preserved")
        else:
            isVul = True 
            output = op.getOutput()
            des = output.getDescendants()
            for i in des:
                if i.getOpcode() == PcodeOp.INT_EQUAL:
                    isVul = False
            if isVul:
                vulResults.add(op.getSeqnum().getTarget())
                print("Warning: a possible vulnerability @" + op.getSeqnum().getTarget().toString() + " since the output of sscanf is not assessed")


    return vulResults

   





#inst_iter = plist.getInstructions(func.getBody(), True)

program = currentProgram
plist = program.getListing()
symbolTable = program.getSymbolTable()
allSymbols = symbolTable.getAllSymbols(False)

allSymbols_sscanf = getSymbols(program, "sscanf$")
allSymbols_sscanf_call = filter(lambda symbol: symbol.getSymbolType() == SymbolType.FUNCTION, allSymbols_sscanf)

fdict={}
for symbol in allSymbols_sscanf_call:
    refs = symbol.getReferences()
    for r in refs:
        if r.getReferenceType().isCall() and r.getFromAddress() is not None:
            f = getFunctionContaining(r.getFromAddress()); 
            if f and (not f.isThunk()):
                if f in fdict:
                    fdict[f].add(symbol)
                else:
                    fdict[f] = set()


#Now get the decomp ready
decomp = DecompInterface()
decomp.openProgram(program)

for k, v in fdict.items():
    analyze(decomp, k, v)

