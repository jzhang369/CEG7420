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
        mnemonic = ins.getMnemonicString()
        if mnemonic == 'CALL':
            print ins 
            callee_addr = ins.getOpObjects(0)[0] # get the first operand of this instruction.
            #print type(callee_addr) 
            callee_Func = getFunctionAt(callee_addr) #getFunctionContaining(callee_addr) should work too. 
            if callee_Func is not None:
                #print callee_Func
                cname = callee_Func.getName()
                print name, "calls ", cname, " which is defined at ", callee_addr
else:
    print "The current address is not contained by a function."
