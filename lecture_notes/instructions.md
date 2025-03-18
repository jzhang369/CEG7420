# **Programming with Instructions in Ghidra**

## **Why Care about Instructions?**

In Ghidra, instructions represent the low-level operations executed by a processor. They are a fundamental aspect of binary analysis. A binary contains machine code. However, Ghidra helps analysts to disassemble *machine code* into **human-readable** *assembly instructions*, allowing analysts to understand program behavior at the instruction level. 

In this section, we refer *instructions* specifically for assembly instructions. Later, we will introduce intermediate representation such as Pcode, which can also be considered as instructions. 

Ghidra provides APIs to interact with instructions through programming, enabling many tasks such as:

+ iterating over instructions,
+ extracting operators (menomic strings) and operands,
+ and performing statistical analysis.

The `Instruction` class in Ghidra offers methods to retrieve details of an instruction such as its mnemonic, operand(s), and references to memory or registers. 


## **Where to Find More Information**

For more detailed information on programming with instructions in Ghidra, refer to the official Ghidra API documentation. The relevant information can be found in your Ghidra installation at: 

docs/GhidraAPI_javadoc/api/ghidra/program/model/listing/Instruction.html


## **Working With Instructions**

### **How to Get An Instruction Object in Ghidra?**

Let us start with `FlatProgramAPI`, and we will find the following methods that can return an instruction object:

+ `getFirstInstruction()` and `getLastInstruction()`
+ `getFirstInstruction(Function function)` - Get the first instruction inside a given function. 
+ `getInstructionAt(Address address)` - Get the instruction at a specific address. 
+ `getInstructionContaining(Address address)` - Get the instruction if this instruction contains this address. 
+ `getInstructionAfter(Address address)` and `getInstructionAfter(Instruction instruction)`
+ `getInstructionBefore(Address address)` and `getInstructionBefore(Instruction instruction)`

```python
# get the first instruction and the last instruction in this binary.
firstInstruction = getFirstInstruction()
print(firstInstruction)

lastInstruction = getLastInstruction()
print(lastInstruction)
```

```python
# enumerate through all functions in this binary, and for each function print out its first instruction. 
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)
for f in allFuncs:
	firstInstruction = getFirstInstruction(f)
 	print("The first instruction of {} function is {}".format(f, firstInstruction))
```

```python
# ask the user to offer an address and then attempt to get the instruction at that address. This address is for the address of the very first byte of the instruction. 
addr = askAddress("Lecture for Instructions", "Please give me an address!")
myInstruction = getInstructionAt(addr)
if myInstruction:
	print(myInstruction)
else:
	print("no instruction found at the address of {}.".format(addr))
```
```python
# ask the user to offer an address and then attempt to get the instruction that contains address. Note: an instruction might be composed of multiple bytes.  
addr = askAddress("Lecture for Instructions", "Please give me an address!")
myInstruction = getInstructionContaining(addr)
if myInstruction:
	print(myInstruction)
else:
	print("no instruction that contains the address of {}.".format(addr))
```

### **How to Enumerate All Instructions Inside a Binary?**

**Option 1:** You can use `getInstructionAfter()` and `getInstructionBefore()` to enumerate all instructions inside a binary. 

```python
# Get the first instruction and then enumerate the one after this, and keep doing that. 
myInstruction = getFirstInstruction()
while myInstruction:
    print(myInstruction)
    myInstruction = getInstructionAfter(myInstruction)
```

**Option 2:** Get the `listing` object, and use the `listing`'s methods. 

```python
# getInstructions returns an iterator of instructions inside this binary
myListing = currentProgram.getListing()
instructionIterator = myListing.getInstructions(True)
for inst in instructionIterator:
    print(inst)
```


### **How to Enumerate All Instructions in a Function?**

**Option 1: ** Enumerate all instructions starting from the first instruction of this function, and check whether this instruction's address is inside the body of this function. 

```python
# display all instructions inside the function indicated by your cursor. 
myFunc = getFunctionContaining(currentAddress)
if myFunc:
	fbody = myFunc.getBody() # this is the body of the function, it is an AddressSetView, a set of addresses. 
	print(myFunc)
	myInstruction = getFirstInstruction(myFunc)
	while myInstruction and fbody.contains(myInstruction.getAddress()): # verify whether the address of this instruction is inside the set of addresses for this function. 
		print("address: {}, instruction: {}".format(myInstruction.getAddress(), myInstruction))
		myInstruction = getInstructionAfter(myInstruction)
else:
	print("No function found at {}.".format(currentAddress))
```


``Option 2:`` Using `getInstructions(AddressSetView addrSet, boolean forward)` of the `listing` object. 