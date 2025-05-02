# **Programming with Basic Blocks in Ghidra**

## **Why Care about Basic Blocks?**


Understanding basic blocks and CFGs is fundamental for program analysis, decompilation, and vulnerability research. A **Basic Block** is a sequence of instructions that execute sequentially without interruption - once execution enters a basic block, it proceeds to the end without branching (except the last instruction in this basic block). It is worth noting that the `CALL` instruction is not considered as a branching instruction. Basic blocks of a function and their connections collectively form the **control flow graph** (CFG) of this function.  

A CFG represents the execution paths between basic blocks in a function (or a program). Each CFG consists of:

+ **Nodes**: each node is a basic block.
+ **Edges**: each edge represents an execution path from one basic block to another basic block through a branching instruction. 

CFGs and basic blocks help analysts to model the program for:

+ Identify loops and unreachable code
+ Detect function boundaries
+ Perform control flow analysis, e.g., constraint analysis
+ Vulnerability discovery
+ Guide static or/and dynamic analysis of binaries. 




## **Where to Find More Information?**

docs/GhidraAPI_javadoc/api/ghidra/program/model/block/BasicBlockModel.html


## **Working with Basic Blocks**

### **How to Enumerate all Basic Blocks in a Binary Using Ghidra?**

The `CodeBlock` class is for basic blocks in Ghidra. 

```python
# To enumerate all basic blocks in a binary.
from  ghidra.program.model.block import BasicBlockModel
myBlockModel = BasicBlockModel(currentProgram)
myBasicBlocks = myBlockModel.getCodeBlocks(monitor)
for i in myBasicBlocks:
	print(i)
```

A `CodeBlock` class has many interesting properties/methods:
+ `getFirstStartAddress()`: get address of the first instruction inside this basic block. 
+ `getSources(TaskMonitor monitor)`: get CodeBlocks that flow into this CodeBlock.
+ `getDestinations(TaskMonitor monitor)`: get CodeBlocks that are flowed to from this CodeBlock.
+ `getFlowType()`: how things flow out of this node.


A `CodeBlockReference` class is for an edge between a source codeblock (i.e., basic block) to its destination codeblock (i.e., basic block). 
+ When you use `getSources(TaskMonitor monitor)` in a `CodeBlock` object, you will get an interator of `CodeBlockReference` objects. Where each `CodeBlockReference` object indicates the address of the last instruction inside the source codeblock and the address of the current codeblock, which is also the address of the first instruction inside this basic block (i.e., the destination of this edge).
+ When you use `getDestinations(TaskMonitor monitor)` in a `CodeBlock` object, you will get an interator of `CodeBlockReference` objects. Where each `CodeBlockReference` object indicates the address of the last instruction inside this codeblock (i.e., the source of this edge) and the address of the first instruction inside the destination codeblock. 

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

### **How to Enumerate Basic Block Objects for a Function Using Ghidra**

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

### **How to Traverse Basic Blocks inside a Function?**

You can use `CodeBlockReference` class discussed in the previous section. 