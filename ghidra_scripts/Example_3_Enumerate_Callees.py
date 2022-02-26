# This is a simple script to enumerate the callees of the current function.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

plist = currentProgram.getListing()
func = getFunctionContaining(currentAddress)

if func != None:
    
    name = func.getName()
    inst_iter = plist.getInstructions(func.getBody(), True)
    
    while inst_iter.hasNext() and not monitor.isCancelled():
        ins = inst_iter.next()
        refs = ins.getReferencesFrom()
        for r in refs:
            if(r.getReferenceType().isCall()):
                toAddr = r.getToAddress()
                # This is one way to get the function name as the symbol name
                sym = getSymbolAt(toAddr)
                sname = sym.getName()

                # This is an alternative way to do it
                calleeFunc = getFunctionAt(toAddr)
                cname = calleeFunc.getName()
                
                # This is another way to do it
                calleeFuncT = getFunctionContaining(toAddr)
                cnameT = calleeFunc.getName()


                print name, "calls", sname, "or say", cname, "or say", cnameT, "at", toAddr
else:
    print "The current address is not contained by a function."
