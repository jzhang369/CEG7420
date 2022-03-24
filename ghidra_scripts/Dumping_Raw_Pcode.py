# This is a simple script to dump the raw pcode.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

plist = currentProgram.getListing()
func = getFunctionContaining(currentAddress)

if func != None:
    name = func.getName()
    inst_iter = plist.getInstructions(func.getBody(), True)
    
    while inst_iter.hasNext() and not monitor.isCancelled():
        ins = inst_iter.next()
        pcodeList = ins.getPcode()
        print("{}".format(ins))
        for pcode in pcodeList:
            print("  {}".format(pcode))
    
else:
    print "The current address is not contained by a function."