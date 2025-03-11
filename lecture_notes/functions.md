# **Programming with Functions in Ghidra**

## **Why Care about Functions?**

Functions are fundamental building blocks for software development. They serve as an effective way to manage complexity through reusability, abstraction, and readability. One major task of software reverse engineering is to figure out function names, interfaces/signatures, logics, and contexts.

+ **Intra-Procedural Analysis**: Analyzing a function in isolation. 
  + Inferring function names
  + Generating control flow graphs
  + Similarity analysis
  + Taint analysis
  + Data flow analysis
  + etc.
+ Inter-Procedural Analysis:Analzying a function or multiple functions by considering the contexts in which they are used. 
  + Generating call graphs
  + Whole-program taint analysis
  + Whole-program data flow analysis
  + Whole-program Symbolic execution
  + etc. 

For this lecture, let's focus on basic programming skills to script Ghidra for intra-procedural analysis. We will NOT foucs on semantic-oriented analysis such as data flow analysis or taint analysis. We will focus on syntactical and statistical analyses.

## **Where to Find More Information?**

You should find most of the information you need from **/docs/GhidraAPI_javadoc/api/ghidra/program/model/listing/Function.html**. 


## **Working with Functions**

### **How to Get a Function Object in Ghidra?**

In `FlatProgramAPI`, you will find the following methods that return a function object:
+ `getFirstFunction()` or `getLastFunction()`
+ `getFunction(String name)`
+ `getFunctionAfter(Address address)`
+ `getFunctionBefore(Address address)`
+ `getFunctionAt(Address entryPoint)`
+ `getFunctionContaining(Address address)`


```python
# Get a function using getFirstFunction()
func = getFirstFunction()
print(func)
```

```python
# Get a function using getFunction(String name)
name = "wsu"
func = getFunction(name)
if func is not None:
	print(func)
else:
	print("Function with {} does not exist.".format(name))
```

```python
# Get a function using getFunctionAt(Address address)
addr = currentAddress # currentAddress is the address indicated by your cursor. 
func = getFunctionAt(addr)
if func is not None:
	print(func)
else:
    print("Function with {} as the entry point does not exist.".format(addr))
```


```python
# Get a function using getFunctionContaining(Address address)
addr = currentAddress # currentAddress is the address indicated by your cursor. 
func = getFunctionContaining(addr)
if func is not None:
	print(func)
else:
	print("Function containing {} does not exist.".format(addr))
```

### **How to Enumerate all Functions in Ghidra?**

+ `getFunctionAfter(Address address)`
+ `getFunctionAfter(Function function)`
+ `getFunctionBefore(Address address)`
+ `getFunctionBefore(Function function)`

```python
# Enumerate all functions using getFunctionAfter(Function function)
func = getFirstFunction()
while func:
	print(func)
	func = getFunctionAfter(func)
```


```python
# Enumerate all functions using getFunctionBefore(Function function)
func = getLastFunction()
while func:
	print(func)
	func = getFunctionBefore(func)
```

```python
# Enumerate all functions using FunctionManager
# docs/GhidraAPI_javadoc/api/ghidra/program/model/listing/FunctionManager.html
# You really do not have to use FunctionManager. 
fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)
for f in allFuncs:
	print(f)
```