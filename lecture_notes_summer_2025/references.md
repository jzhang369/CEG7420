# **Ghidra Scripting: Working with References**

## **Why References Matter?**

In Ghidra, a **reference** represents a relationship between two addresses in a binary. For example, a reference can represent:

+ control flow changes
+ function call
+ data access


Each reference will contain two addresses, 
+ a `FROM` address and 
+ a `TO` address. 
 

References are very useful for automating binary analysis tasks and improving reverse engineering efficiency. 

+ They free your program from parsing instructions and interpreting semantic meanings of highly diversified mnemonics.

+ They help analysts understand how instructions and data interact, aiding in reconstructing program logics.

## **Where to Find More Information?**

For more detailed information on programming with references in Ghidra, refer to the official Ghidra API documentation. The relevant information can be found in your Ghidra installation at: 

docs/GhidraAPI_javadoc/api/ghidra/program/model/symbol/Reference.html

## **Working with References**

### **Retrieving one Reference Object**

+ `FlatProgramAPI`
+ `ReferenceManager`: `currentProgram.getReferenceManager()`. This class gives you an enriched set of methods to retrieve information about references. 


```python
# enumerate all references from and to the currentAddress
print("currentAddress: {}".format(currentAddress))
for i in getReferencesFrom(currentAddress):
	print("a ref from this address: {}".format(i))
for i in getReferencesTo(currentAddress):
	print("a ref to this address: {}".format(i))
```

```python
refManager = currentProgram.getReferenceManager()
for i in refManager.getReferencesFrom(currentAddress):
	print("a ref from this address: {}".format(i))
for i in refManager.getReferencesTo(currentAddress):
	print("a ref to this address: {}".format(i))
```

### **How to Enumerate References Objects for a Function Using Ghidra**

You can get the body of the function, and enumerate all addresses in its body. Next, you can use `getReferencesFrom(Address)` and `getReferencesTo(Address)` to retrieve references of this address. 

```python
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




### **How to Enumerate References Objects for an Instruction Using Ghidra**

When you put `currentAddress` as the entry address of a function, this program is going to show you all references from instructions that call this function. This suggests a more efficient way to enumerate all callers of this function. 

```python
inst = getInstructionAt(currentAddress)
if inst:
	addr = inst.getAddress()
	for i in getReferencesFrom(addr):
		print("Ref from {} {} is {}".format(addr, inst, i))
	for i in getReferencesTo(addr):
		print("Ref to {} {} is {}".format(addr, inst, i))	
```

### **Reference Types**

Use this to check the reference type. 
```python
allRefs[0].getReferenceType() == RefType.CONDITIONAL_JUMP
```

For a reference, you can use `getReferenceType()` to get a `RefType` object. The `RefType` class contains detailed information for all types supported by Ghidra's `Reference` class. Examples include, but are not limited to:
+ CONDITIONAL_JUMP
+ UNCONDITIONAL_JUMP
+ CONDITIONAL_CALL
+ UNCONDITIONAL_CALL
+ COMPUTED_CALL

The `RefType` class also offers a set of methods to evaluate the type of the reference. For example, you can use `isCall()` to check whether this reference is a `CALL` reference, regardless of its specific type as CONDITIONAL_CALL, UNCONDITIONAL_CALL, COMPUTED_CALL, and etc. You can use the similar way process `JUMP` instructions. 

Let's have one example - Enumerate all `JUMP` references in a function, and print out its specific `RefType`.

```python
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	# getInstructions returns an iterator of instructions inside this binary
	myListing = currentProgram.getListing()
	instructionIterator = myListing.getInstructions(True)
	for inst in instructionIterator:
		addr = inst.getAddress()
		for ref in getReferencesFrom(addr):
			if ref.getReferenceType().isJump():
				print("{} with the specific type of {}".format(ref, ref.getReferenceType().getName()))
```


### **Application 1: Enumerate All Callees of the Current Function**

```python
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	fbody = myFunc.getBody() #fbody is an object of AddressSetView
	print(myFunc)
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

```python
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	addr = myFunc.getEntryPoint()
	for ref in getReferencesTo(addr):
		if ref.getReferenceType().isCall():
			callerAddr = ref.getFromAddress()
			callerFunc = getFunctionContaining(callerAddr)
			print("{} is called by {} at {}".format(myFunc, callerFunc, callerAddr))

```


### **Application 3: Identify All Functions with Loop(s)**

```python
funcsWithLoop = set()
myListing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)
for f in allFuncs:
    f_body = f.getBody()
    instructionIterator = myListing.getInstructions(f_body, True)
    for inst in instructionIterator:
    	jumpRefs = filter(lambda x: x.getReferenceType().isJump() and f_body.contains(x.getToAddress()) and x.getToAddress().subtract(inst.getAddress()) < 0, getReferencesFrom(inst.getAddress()))
    	if len(list(jumpRefs)) > 0:
    		funcsWithLoop.add(f)

print("Functions with loop:")
for f in funcsWithLoop:
	print(f)

```


### **Application 4: Identify All Recursion Functions**

```python
funcsRecursion = set()
myListing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)
for f in allFuncs:
	entryAddr = f.getEntryPoint()
	f_body = f.getBody()
	instructionIterator = myListing.getInstructions(f_body, True)
	for inst in instructionIterator:
		callRefs = filter(lambda x: x.getReferenceType().isCall() and x.getToAddress().equals(entryAddr), getReferencesFrom(inst.getAddress()))
    	if len(list(callRefs)) > 0:
    		funcsRecursion.add(f)

print("Recursion Functions:")
for f in funcsRecursion:
	print(f)
```


### **Discussion: What is the `INDIRECTION` reference to a function?**


