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

### **How to Enumerate References Objects for an Instruction Using Ghidra**


### **Application 1: Enumerate All Callees of the Current Function**

### **Application 2: Enumerate All Callers of the Current Function**