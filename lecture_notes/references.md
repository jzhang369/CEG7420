# **Programming with References in Ghidra**

## **Why Care about References?**

In Ghidra, a **reference** represents a relationship between two addresses in a binary. For example, a reference can represent:

+ function call
+ data access
+ control flow changes

Each reference will contain two addresses, a `FROM` address and a `TO` address. References are very useful because they free your program from parsing instructions and interpreting semantic meanings of highly diversified mnemonics. Specifically, references help analysts understand how instructions and data interact, aiding in reconstructing program logics. 

References are very useful for automating binary analysis tasks and improving reverse engineering efficiency. 

## **Where to Find More Information?**

docs/GhidraAPI_javadoc/api/ghidra/program/model/symbol/Reference.html

## **Working with References**

### **How to Get an Reference Object Using Ghidra?**

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

### **Application 2: Enumerate All Callers of the Current Function**


### **Application 3: Identify All Functions with Loop(s)**

### **Application 4: Identify All Recursion Functions**


