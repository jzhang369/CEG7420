# **Ghidra Scripting: Working with References**

## **Why References Matter?**

In Ghidra, a reference consists of two addresses:  
- A `FROM` address  
- A `TO` address  

A **reference** represents a relationship between two addresses and can indicate various interactions, such as:  
- Control flow changes  
- Function calls  
- Data access  

References are very useful for automating binary analysis and enhancing reverse engineering efficiency. They provide several key benefits:  

- They eliminate the need to parse instructions and interpret the semantic meaning of diverse mnemonics.  
- They assist analysts in understanding how instructions and data interact, aiding in the reconstruction of program logic.  

An example: <FROM: 00102788, To: 00105b60, Type: Unconditional_Call> because at 0x00102788, there is an instruction `CALL 0x00105b60`


## **Where to Find More Information?**

For more detailed information on programming with references in Ghidra, refer to the official Ghidra API documentation. The relevant information can be found in your Ghidra installation at: 

docs/GhidraAPI_javadoc/api/ghidra/program/model/symbol/Reference.html


## **Working with References**

### **Retrieving Reference Objects**

Given an address, such as `addr`, you can identify:  
- References where the `FROM` address is `addr`.  
- References where the `TO` address is `addr`.  

This address can be any location within the binary, such as the address of an instruction, the entry point of a function, or the address of a byte.  

Both the `FlatProgramAPI` and `ReferenceManager` classes provide methods to retrieve references associated with a specific address. It is important to note that a single address may be associated with multiple references.  A `ReferenceManager` object can be obtained using `currentProgram.getReferenceManager()`.

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang
# enumerate all references from and to an address
addr = askAddress("Ghidra Scripting - References", "Please input an address:")
for i in getReferencesFrom(addr):
	print("a ref from this address: {}".format(i))
for i in getReferencesTo(addr):
	print("a ref to this address: {}".format(i))
```


```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

addr = askAddress("Ghidra Scripting - References", "Please input an address:")

refManager = currentProgram.getReferenceManager()

for i in refManager.getReferencesFrom(addr):
	print("a ref from this address: {}".format(i))
for i in refManager.getReferencesTo(currentAddress):
	print("a ref to this address: {}".format(addr))
```

### **Enumerating Reference Objects Relevant to a Function**

Since a reference is always associated with an address, you can enumerate references relevant to a function by:  

1. **Enumerating all addresses** within the function.  
2. **Retrieving references** for each address.  

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	print(myFunc.getName())
	fbody = myFunc.getBody()
	for addr in fbody.getAddresses(True):
		for i in getReferencesFrom(addr):
			print("a ref from this address {}: {}".format(addr, i))
		for i in getReferencesTo(addr):
			print("a ref to this address {}: {}".format(addr, i))
```

### **Enumerating Reference Objects Relevant to an Instruction**

Again, a reference is always associated with an address. You can obtain the address of an instruction and then retrieve all references from or to that address.  

For example, let's get the first instruction of a function and identify references associated with this instruction.  

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	inst = getFirstInstruction(myFunc)
	if inst:
		addr = inst.getAddress()
		for i in getReferencesFrom(addr):
			print("a ref from this address {}: {}".format(addr, i))
		for i in getReferencesTo(addr):
			print("a ref to this address {}: {}".format(addr, i))
```

### **Understanding Reference Types**

A reference characterizes the relationship between the `FROM` address and the `TO` address. This relationship can represent various interactions, such as:  

- **Function Call:** The instruction at the `FROM` address calls a function whose entry point is the `TO` address.  
- **Unconditional Jump:** The instruction at the `FROM` address unconditionally jumps to the instruction at the `TO` address.  
- **Conditional Jump:** The instruction at the `FROM` address conditionally jumps to the instruction at the `TO` address.  
- **Data Access:** The instruction at the `FROM` address reads/writes data at the `TO` address.  
- **...** (Additional reference types)  

For a reference, you can use the `getReferenceType()` method to obtain a `RefType` object, which indicates the type of the reference. Examples of reference types include, but are not limited to:  

- `CONDITIONAL_JUMP`  
- `UNCONDITIONAL_JUMP`  
- `CONDITIONAL_CALL`  
- `UNCONDITIONAL_CALL`  
- `COMPUTED_CALL`  

The `RefType` class provides several methods to evaluate the type of a reference. For instance:  

- Use `isCall()` to determine if the reference is a `CALL` type, regardless of whether it is `CONDITIONAL_CALL`, `UNCONDITIONAL_CALL`, `COMPUTED_CALL`, etc. Similarly, you can use analogous methods to identify `JMP` instructions.  
- But if you can always check the specific type of a reference such as `UNCONDITIONAL_JUMP`. You can use `ref.getReferenceType() == RefType.UNCONDITIONAL_JUMP`. 

Here’s an example: Enumerate all `JMP` references **from** each instruction in a binary, regardless of their specific types, such as `CONDITIONAL_JUMP` or `UNCONDITIONAL_JUMP`.  

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

myListing = currentProgram.getListing()
instructionIterator = myListing.getInstructions(True)
for inst in instructionIterator:
	addr = inst.getAddress()
	allRefsFromAddr = getReferencesFrom(addr)
	for ref in allRefsFromAddr:
		if ref.getReferenceType().isJump():
			print("{} with the specific type of {}".format(ref, ref.getReferenceType().getName()))
```

Here’s another example: Enumerate all `UNCONDITIONAL_JUMP` references **from** each instruction in a binary. 

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

from ghidra.program.model.symbol import RefType

myListing = currentProgram.getListing()
instructionIterator = myListing.getInstructions(True)
for inst in instructionIterator:
	addr = inst.getAddress()
	allRefsFromAddr = getReferencesFrom(addr)
	for ref in allRefsFromAddr:
		if ref.getReferenceType() == RefType.UNCONDITIONAL_JUMP:
			print("{} with the specific type of {}".format(ref, ref.getReferenceType().getName()))
```


### **Application 1: Enumerate All Callees of the Current Function**

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

#find all callees of the current function.

myFunc = getFunctionContaining(currentAddress)
if myFunc:
	print(myFunc)
	
	fbody = myFunc.getBody() #fbody is an object of AddressSetView
	myListing = currentProgram.getListing()
	instructionIterator = myListing.getInstructions(fbody, True)

	for inst in instructionIterator:
		addr = inst.getAddress()
		for ref in getReferencesFrom(addr):
			if ref.getReferenceType().isCall():
				calleeAddr = ref.getToAddress()
				calleeFunc = getFunctionAt(calleeAddr)
				print("{} at {} calls {}".format(myFunc, addr, calleeFunc))
```

### **Application 2: Enumerate All Callers of the Current Function**

We already implemented two solutions by:  
1. Parsing instruction operands, and  
2. Using the `getFlow()` method of the `Instruction` class.  

For either implementation, we need to enumerate all instructions within the binary. The implementation using `getFlow()` is shown below.  

```python
# old implementation
callers = set()

myFunc = getFunctionContaining(currentAddress)
if myFunc:
	# getInstructions returns an iterator of instructions inside this binary
	myListing = currentProgram.getListing()
	instructionIterator = myListing.getInstructions(True)
	for inst in instructionIterator:
		if inst.getMnemonicString().startswith("CALL"):
			for calleeAddr in inst.getFlows():
				if myFunc.getEntryPoint() == calleeAddr:
					callerFunc = getFunctionContaining(inst.getAddress())
					print("Caller: {} at {} calls {}".format(callerFunc, inst.getAddress(), myFunc))
					callers.add(callerFunc)

print(callers)
```

Let’s see how `reference` can assist in simplifying the implementation:  
- Get the entrypoint of the current function.  
- Retrieve references **to** this entrypoint and filter for `CALL` references only.  
- Extract the `FROM` addresses from these references.  
- For each of these addresses, identify the function that contains the address — this function is a caller.  

**No need to enumerate all instructions of this binary!**

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

#find all callers of the current function.

myFunc = getFunctionContaining(currentAddress)
if myFunc:
	entrypoint = myFunc.getEntryPoint()
	for ref in getReferencesTo(entrypoint):
		if ref.getReferenceType().isCall():
			callerInstAddr = ref.getFromAddress()
			callerFunc = getFunctionContaining(callerInstAddr)
			print("{} is called by {} at {}".format(myFunc, callerFunc, callerInstAddr))
```


### **Application 3: Identify All Functions with Loop(s)**

All you need to do is:  

1. Enumerate all instructions within a function.  
2. Identify the `CALL` reference **from** each instruction.  
3. Check whether the `TO` address:  
   - Is within the body of the current function (this can be ignored as it is always the case).  
   - Is smaller than the address of the current instruction (indicating a backward jump).

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

#find all callers of the current function.

funcsWithLoop = set()

myListing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)

for f in allFuncs:
    f_body = f.getBody()
    
    instructionIterator = myListing.getInstructions(f_body, True)
 
    for inst in instructionIterator:
    	allRefsFromInst = getReferencesFrom(inst.getAddress())
    	allJumpRefsFromInst = filter(lambda x: x.getReferenceType().isJump(), allRefsFromInst)
    	allBackwardJumpRefsFromInst = filter(lambda x: x.getFromAddress() > x .getToAddress(), allJumpRefsFromInst) 
    	if len(allBackwardJumpRefsFromInst) > 0:
    		funcsWithLoop.add(f)

print("Functions with loop:")
for f in funcsWithLoop:
	print(f)
```

### **Application 4: Identify All Recursion Functions**

To identify recursive functions, check whether any instruction within a function makes a call to the function itself.  

```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

#find all recursion functions.

funcsWithRecursion = set()

myListing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)

for f in allFuncs:
    f_body = f.getBody()
    
    instructionIterator = myListing.getInstructions(f_body, True)
 
    for inst in instructionIterator:
    	allRefsFromInst = getReferencesFrom(inst.getAddress())
    	allCallRefsFromInst = filter(lambda x: x.getReferenceType().isCall(), allRefsFromInst)
    	allSelfCallRefsFromInst = filter(lambda x: x.getToAddress() == f.getEntryPoint(), allCallRefsFromInst) 
    	if len(allSelfCallRefsFromInst) > 0:
    		funcsWithRecursion.add(f)

print("Functions with recusion:")
for f in funcsWithRecursion:
	print(f)
```

Can you figure out a simpler solution using references? 


```python
# Ghidra Scripting: References 
# @category: GhidraScripting 
# @author: Junjie Zhang

#find all recursion functions.

funcsWithRecursion = set()

myListing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)

for f in allFuncs:
    
    entryPoint = f.getEntryPoint()
    f_body = f.getBody()

    allRefsToEntryPoint = getReferencesTo(entryPoint)
    allCallRefsToEntryPoint = filter(lambda x: x.getReferenceType().isCall(), allRefsToEntryPoint)
    allSelfCallRefsToEntryPoint = filter(lambda x: f_body.contains(x.getFromAddress()), allCallRefsToEntryPoint)
    
    if len(allSelfCallRefsToEntryPoint) > 0:
    	funcsWithRecursion.add(f)

print("Functions with recusion:")
for f in funcsWithRecursion:
	print(f)
```