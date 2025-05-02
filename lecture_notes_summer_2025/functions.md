# **Ghidra Scripting: Working with Functions**

## **Why Functions Matter?**

Functions are fundamental units of modularity and abstraction in software development. They enable developers to decompose complex systems into smaller, manageable components, facilitating 
+ Code reuse, 
+ Readability, 
+ Maintainability, and 
+ Testing. 

In the context of software reverse engineering, functions serve as critical analysis targets. Typical function-oriented reverse engineering tasks include, but are not limited to, 

+ Recover function boundaries, 
+ Infer meaningful names, 
+ Reconstruct signatures (including return types and parameters), and 
+ Understand the logic implemented within each function. 

The indepth understanding of functions is essential for tasks such as vulnerability discovery, malware analysis, and binary lifting.

Function analysis can generally be categorized into two strategies:

+ **Intra-Procedural Analysis**: This approach focuses on analyzing a single function in isolation, without considering its interactions with other functions. Common tasks include:
  + Inferring function names
  + Generating control flow graphs (CFGs)
  + Performing similarity analysis
  + Conducting taint analysis
  + Examining data flow within the function
  + And more

+ **Inter-Procedural Analysis**: This strategy involves analyzing one or more functions while taking into account their calling contexts and interactions with other functions. Typical applications include: 
  + Building call graphs
  + Performing whole-program taint analysis
  + Executing whole-program data flow analysis
  + Applying symbolic execution across function boundaries
  + And more

In this lecture, we will focus on foundational scripting skills in Ghidra to support intra-procedural analysis. Specifically, we will work on syntactic analysis techniques rather than deeper semantic analyses such as taint tracking or data flow analysis.

## **Where to Find More Information?**


Most relevant documentation for working with functions in Ghidra can be found in the official Javadoc at:

**/docs/GhidraAPI_javadoc/api/ghidra/program/model/listing/Function.html**

This resource provides detailed descriptions of the Function class and its methods, which are essential for scripting and analyzing functions programmatically.


## **Working with Functions**

### **Retrieving Function Objects in Ghidra**


Ghidra's `FlatProgramAPI` provides several convenient methods to access Function objects within a binary. These methods allow you to retrieve specific functions based on their name, address, or relative position:

- `getFirstFunction()` / `getLastFunction()` : Retrieves the first or last function in the program.
  
- `getFunction(String name)` : Returns a function by its name, if it exists.



- `getFunctionAt(Address entryPoint)` : Retrieves a function located exactly at the given entry point address.

- `getFunctionContaining(Address address)` : Returns the function that contains the specified address (e.g., the address of an instruction or variable).

- `getFunctionAfter(Address address)`  : Gets the next function after the specified address.

- `getFunctionBefore(Address address)` : Gets the previous function before the specified address.

These methods form the basis for navigating and analyzing functions through scripting in Ghidra.

Examples: 

```python
# Get a function using getFirstFunction()
func = getFirstFunction()
print(func)
```

```python
# Get a function using getFunction(String name)
name = "xyz"
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

Layout of functions in the `.text` section. 


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