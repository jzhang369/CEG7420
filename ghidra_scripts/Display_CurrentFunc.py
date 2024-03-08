# This is a simple script to enumerate the basic information of the current function.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

plist = currentProgram.getListing()

func = getFunctionContaining(currentAddress) # not getFunctionAt(currentAddress)

if func != None and (not monitor.isCancelled()): 
    name = func.getName()
    entryAddr = func.getEntryPoint()
    minAddr = func.getBody().getMinAddress()
    maxAddr = func.getBody().getMaxAddress()
    paras = func.getParameters()
    parasLen = len(paras)

    #count the number of instructions for this function. 
    inst_iter = plist.getInstructions(func.getBody(), True)
    counter = 0
    while inst_iter.hasNext() and not monitor.isCancelled():
        counter = counter + 1
        ins = inst_iter.next()
        pcodeList = ins.getPcode()
        print ins
        for i in pcodeList:
            print "\t\t", i         

    print name, entryAddr, minAddr, maxAddr, parasLen, counter;

