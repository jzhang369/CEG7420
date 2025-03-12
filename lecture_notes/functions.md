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
+ **Inter-Procedural Analysis**: Analzying a function or multiple functions by considering the contexts in which they are used. 
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


### **How to Retrieve Useful Information from a Function Object**

What properities of a function that might be of your interest? 
+ function name
+ calling convention
+ function signature including returned type, parameters and their corresponding types
+ entry point (the address of the first instruction of this function)
+ exit point (the address of the last instruction of this function)
+ size of the function (the number of bytes for the body of the function)
+ type of the function
  + internal function? 
  + external function? 
  + inline function? 
  + thunk function?
+ Parameters
  + get the name & type of each parameter
  + set the name & type of each parameter
+ Local Variables
  + get the name & type of each local variable
  + set the name & type of each local variable
+ Returned Variable
  + The name and type of the returned variable


```python
# Retrieve some properties of a function object.
# @category: CEG7420.Demo
# @author: Junjie Zhang

from ghidra.program.model.symbol import SourceType


fm = currentProgram.getFunctionManager()
allFuncs = fm.getFunctions(True)

flag = True

for f in allFuncs:

    f_body = f.getBody() #f_body is AddressSetView
    
    print("-"*10)
    print("name:\t\t{}".format(f.getName()))
    print("calling convention:\t\t{}".format(f.getCallingConventionName()))
    print("signature:\t\t{}".format(f.getSignature()))
    print("entry address:\t\t{}".format(f.getEntryPoint()))
    print("exit address:\t\t{}".format(f_body.getMaxAddress()))
    print("size of function body:\t\t{}".format(f_body.getMaxAddress().subtract(f.getEntryPoint())))
    print("internal function:\t\t{}".format(not f.isExternal()))
    print("external function:\t\t{}".format(f.isExternal()))
    print("inline function:\t\t{}".format(f.isInline()))
    print("thunk function:\t\t{}".format(f.isThunk()))
    
    
    parameter_cnt = f.getParameterCount()
    parameter_list = f.getParameters()
    for i in parameter_list:
        print("parameter:\t\t{}".format(i))
        
        # This is to set the name of the first parameter we see over all functions. 
        if flag:
            flag = False
            i.setName("CEG7420_Temp", SourceType.USER_DEFINED) 

    local_variables = f.getLocalVariables()
    for i in local_variables:
        print("local variable:\t\t{}".format(i))
        
        
    ret_variable = f.getReturn()
    ret_variable_type = f.getReturnType()
    
    print("Returned Varaible & Type:\t\t{}:{}".format(ret_variable, ret_variable_type))
```