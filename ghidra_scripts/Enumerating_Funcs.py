# This is a simple script to enumerate functions in a binary. It reports the name, the entry address, the minimal address, the maximal address, and the number of parameters.
# @category: CEG7420.Demo
# @author: Junjie Zhang

func = getFirstFunction()
plist = currentProgram.getListing()
while func != None and (not monitor.isCancelled()): 
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

    print name, entryAddr, minAddr, maxAddr, parasLen, counter;
    #print(paras);
    func = getFunctionAfter(func)

