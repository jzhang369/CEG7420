# **Ghidra Scripting: Working with Basic Blocks**

## By [**Dr. Junjie Zhang**](https://jzhang369.github.io/)

## **Why Basic Blocks Matter?**

A **basic block** is a sequence of consecutive instructions in a program with the following characteristics:  

- **Single Entry Point:** Execution always starts at the first instruction of the block and cannot be entered at any other point within the block.  
- **Single Exit Point:** Execution always exits from the last instruction of the block, either through a jump, or branch.  
- **Linear Flow:** There are no jumps or branches within the block itself, except at the end.  

It is worth noting that when constructing basic blocks, function calls are generally treated as regular instructions rather than as jumps or branches. 

### **Example:**  
```assembley
0x1000: MOV EAX, 5  
0x1004: CALL 0x2000      ; Function call (not an exit point)  
0x1009: ADD EAX, 3  
0x100C: CMP EAX, 8  
0x1010: JNZ 0x1020       ; Conditional jump (exit point)
```
+ The basic block starts at 0x1000 and continues through the function call at 0x1004.
+ The function call is treated as a regular instruction, not a control flow transfer within the function.
+ The basic block ends at the conditional jump instruction (0x1010), which is the actual exit point.
+ The instructions from 0x1000 to 0x100C are part of the same basic block, despite the function call.
 
**Basic blocks** are fundamental building blocks for constructing a **Control Flow Graph (CFG)**. a CFG is typically generated for one function. Therefore, the process of constructing a CFG from basic blocks belongs to intra-procedural analysis. Basic blocks of *a function* and their connections collectively form the CFG of this function.  

+ **Nodes**: each node is a basic block.
+ **Edges**: each edge represents an execution path from one basic block to another basic block through a branching instruction. 

By connecting basic blocks based on control flow, a CFG provides a graphical representation of how control passes through a program.  

CFGs and basic blocks help analysts to model the program for:

+ Understanding the structure of the program
+ Profiling the coverage at runtime
+ Perform control flow analysis, e.g., constraint and reachability analysis
+ Vulnerability discovery
+ Guide static or/and dynamic analysis of binaries. 




## **Where to Find More Information?**

For more detailed information on working with basic blocks in Ghidra, you can refer to the following documentation:


docs/GhidraAPI_javadoc/api/ghidra/program/model/block/BasicBlockModel.html


## **Working with Basic Blocks**

### **Enumerating all Basic Blocks in a Binary**

To generate basic blocks for a binary, you will need to use the `BasicBlockModel` class. Each basic block is a sequence of consecutively executed instructions.  


Important Methods in `BasicBlockModel`:

1. **`getCodeBlocks(TaskMonitor monitor)`**: Get an iterator over the code blocks in the entire program.
2. **`getCodeBlocksContaining(Address addr, TaskMonitor monitor)`**: Get all the Code Blocks containing the address.
3. **`getCodeBlocksContaining(AddressSetView addrSet, TaskMonitor monitor)`**: Get an iterator over CodeBlocks which overlap the specified address set.
4. **`getFlowType(CodeBlock block)`**: Return in general how things flow out of this node. (similar to the reference type). 

An example - **enumerating all basic blocks in a binary**

```python
# To enumerate all basic blocks in a binary.
from  ghidra.program.model.block import BasicBlockModel
myBlockModel = BasicBlockModel(currentProgram)
myBasicBlocks = myBlockModel.getCodeBlocks(monitor)
for i in myBasicBlocks:
	print(i)
```

Another example - **Enumerating Basic Block Objects in a Function**

```python
from  ghidra.program.model.block import BasicBlockModel

myBlockModel = BasicBlockModel(currentProgram)
currentFunc = getFunctionContaining(currentAddress)
if currentFunc:
	fbody = currentFunc.getBody()
	myBasicBlocks = myBlockModel.getCodeBlocksContaining(fbody, monitor)
	for i in myBasicBlocks:
		name = i.getName()
		print('Name: {}, Starting Address: {}'.format(name, i.getFirstStartAddress()))
```

### **Understanding the `CodeBlock` class**


The `CodeBlock` class represents these basic blocks in Ghidra. It provides methods for identifying and interacting with individual basic blocks within a program.  



Important Methods in `CodeBlock`:

1. **`Address[] getStartAddresses()`**: Get all the entry points to this block. 
2. **`Address getFirstStartAddress()`**: Return the first start address of the CodeBlock.
3. **`FlowType getFlowType()`**: Return, in theory, how things flow out of this node. 
4. **`CodeBlockReferenceIterator getSources(TaskMonitor monitor)`**: Get an Iterator over the CodeBlocks that flow into this CodeBlock.
5. **`CodeBlockReferenceIterator getDestinations(TaskMonitor monitor)`**: Get an Iterator over the CodeBlocks that are flowed to from this CodeBlock.

### **Understanding the `CodeBlockReference` Class**

For a basic block object, its `getSources(TaskMonitor monitor)` method will return Iterator of <u>**`CodeBlockReference`**</u> over the CodeBlocks that flow into this CodeBlock; its `getDestinations(TaskMonitor monitor)` will return an Iterator of <u>**`CodeBlockReference`**</u> over the CodeBlocks that are flowed to from this CodeBlock. 

The `CodeBlockReference` class represents an edge between a source code block (basic block) and its destination code block (basic block).  

- When you use the `getSources(TaskMonitor monitor)` method on a `CodeBlock` object, you receive an iterator of `CodeBlockReference` objects. Each `CodeBlockReference` object provides:  
  - **`getSourceAddress()`**: The address of the last instruction in the source code block.  
  - **`getDestinationAddress()`**: The address of the first instruction in the current code block, which is the destination of the edge.  

- Similarly, when you use the `getDestinations(TaskMonitor monitor)` method on a `CodeBlock` object, you receive an iterator of `CodeBlockReference` objects. Each `CodeBlockReference` object provides:  
  - **`getSourceAddress()`**: The address of the last instruction in the current code block, which serves as the source of the edge.  
  - **`getDestinationAddress()`**: The address of the first instruction in the destination code block.  





```python
from  ghidra.program.model.block import BasicBlockModel

myBlockModel = BasicBlockModel(currentProgram)
myBasicBlocks = myBlockModel.getCodeBlocks(monitor)
for i in myBasicBlocks:
	name = i.getName()
	srcs = i.getSources(monitor)
	dsts = i.getDestinations(monitor)
	print('Name: {}, Starting Address: {}'.format(name, i.getFirstStartAddress()))
	while srcs.hasNext():
		s = srcs.next()
		print("src ref: {}".format(s))
	while dsts.hasNext():
		d = dsts.next()
		print("dst ref: {}".format(d))
```


### **Application: Reachability Analysis**  

Given a basic block, identify all basic blocks from which the current basic block is reachable.  


```python
# Ghidra Scripting: Basic Blocks 
# @category: GhidraScripting 
# @author: Junjie Zhang

# identify all basic blocks that can reach a given block.
from  ghidra.program.model.block import BasicBlockModel

addr = askAddress("Ghidra Scriting - Basic Blocks", "Give me any address in a basic block")
myBlockModel = BasicBlockModel(currentProgram)
targetBasicBlockList = myBlockModel.getCodeBlocksContaining(addr, monitor)

if not targetBasicBlockList:
	exit()

targetBasicBlock = targetBasicBlockList[0]

processedBasicBlocks = []
toBeProcessedBasicBlocks = [targetBasicBlock]

while len(toBeProcessedBasicBlocks) > 0:
	one = toBeProcessedBasicBlocks.pop(0) # to dequeue the array
	processedBasicBlocks.append(one)
	srcs = one.getSources(monitor)
	while srcs.hasNext():
	 	s = srcs.next()
		srcAddr = s.getSourceAddress()
		srcBasicBlockList = myBlockModel.getCodeBlocksContaining(srcAddr, monitor)
		if srcBasicBlockList:
			srcBasicBlock = srcBasicBlockList[0]
			if not (srcBasicBlock in processedBasicBlocks): # this srcBasicBlock has not been processed before
				toBeProcessedBasicBlocks.append(srcBasicBlock)

print("The Basic Block {} is reachable from the following Basic Blocks:".format(targetBasicBlock.getName()))
print([i.getName() for i in processedBasicBlocks])
```