# **Ghidra Scripting: Introduction to Ghidra Programming**

## **Why Ghidra Scripting Matters?**

Ghidra scripting allows reverse engineers to automate common analysis tasks, reduce manual work, and explore deeper program semantics using custom scripts. With scripting, users can create:

+ Custom automation pipelines,
+ Interactive or headless batch analyses,
+ Data extraction and transformation routines,
+ Extensions of Ghidra’s capabilities.

The scripting environment is built on top of Java and Jython (Python for Java).

## **Scripting Modes in Ghidra**

Ghidra scripts can be written and executed using multiple scripting modes:

### **Interactive (GUI-Based)**

This is the default scripting mode within the Ghidra GUI. You can create, edit, and run scripts via the `Script Manager`. The context includes the currently open program and address of the cursor.

Pros:
+ Immediate feedback and testing,
+ Direct GUI integration (e.g., currentAddress, highlights).
    

### **Headless Mode (Command Line)**

Ghidra provides `analyzeHeadless`, a command-line interface to run scripts on one or more binaries outside of the GUI.

```bash
analyzeHeadless <ProjectDir> <ProjectName> -import <Binary> -scriptPath <PathToScripts> -postScript <YourScript> [args...]
```

Pros:
+ Batch processing,
+ Integration with automation pipelines,
+ No GUI overhead.

### **Third-Party Interfaces (e.g., PyGhidra)**

[`PyGhidra`](https://pypi.org/project/pyghidra/) is a Python library that provides direct access to the Ghidra API.


**This mode is useful when integrating Ghidra with Python-based tooling such as Jupyter notebooks or static analysis pipelines.**

## **How Scripting Works in Ghidra**

Every script you write in Ghidra extends the `GhidraScript` class. The `GhidraScript` class extends the `FlatProgramAPI` class. Their relationship is characterized as follows. 

```text
Your Script
└── inherits ──> GhidraScript
                  └── extends ──> FlatProgramAPI
```

+ `FlatProgramAPI` internally holds a reference to the current ProgramDB object and offers numerous methods for interacting with binary constructs such as memory, functions, instructions, addresses, and symbols.
+ `GhidraScript` is the abstract base class for scripting in Ghidra. It extends FlatProgramAPI, inheriting its analysis methods. It additionally provides interactive utilities such as askString, askAddress, and access to monitor for progress reporting and cancellation.

## **Example Script Skeleton**
```python
# Ghidra Scripting Description: Our First Script
# @category: GhidraScripting
# @author: Junjie Zhang

print("Hello World!")
```

Load this folder into Ghidra. 
