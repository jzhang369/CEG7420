# This is a simple script to enumerate the callers of the current function.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

plist = currentProgram.getListing()
func = getFunctionContaining(currentAddress)

if func != None:
   
    entry_addr = func.getEntryPoint()
    refs = getReferencesTo(entry_addr)

    for r in refs:
        if r.getReferenceType().isCall():
            addr = r.getFromAddress()
            caller = getFunctionContaining(addr)
            print caller.getName(),"at", caller.getEntryPoint() ,"calls", func.getName(), "in", addr
else:
    print "The current address is not contained by a function."
