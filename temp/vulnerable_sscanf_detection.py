# This is a simple script to detect vulnerability introduced by a unsanitized sscanf.
# The idea can be traced back to this article. https://www.zerodayinitiative.com/blog/2019/7/16/mindshare-automated-bug-hunting-by-modeling-vulnerable-code
# @category: CEG7420.Demo
# @author: Junjie Zhang

program = currentProgram
symbolTable = program.getSymbolTable()
allSymbols = symbolTable.getAllSymbols(False)
while allSymbols.hasNext():
    sym = allSymbols.next()
    sym_name_str = sym.getName()
    sym_type_str = sym.getSymbolType().toString()
    sym_address_str = sym.getAddress().toString()

    if "sscanf" in sym_name_str:
        print(sym_name_str + " : " + sym_type_str + ":" + sym_address_str); 

    #if "sscanf" in sym_name_str and sym_type_str == "Function": 
    #    print(sym.getName() + " : " + sym.getSymbolType().toString()) 
    #    refs = sym.getReferences()
    #    for r in refs:
    #        print("from: " + r.getFromAddress().toString() + " to: " + r.getToAddress().toString() + " isCall: " + str(r.getReferenceType().isCall()) + " isJump: " +  str(r.getReferenceType().isJump()))
    
