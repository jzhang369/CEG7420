---
marp: true
author: Junjie Zhang
theme: gaia
title: Taint Analysis
paginate: true
---

# Taint Analysis

+ CEG 7420 Reverse Engineering and Program Analysis
+ Junjie Zhang
+ junjie.zhang@wright.edu
+ Wright State University

---

# Learning Objectives

+ Defining Taint Analysis
+ Its Security Applications
+ Implementing Taint Analysis
  + Using Static Analysis
  + Using Dynamic Analysis
+ Implementing Static Taint Analysis with P-Code Using Ghidra

---

# Taint Analysis

It is a software analysis technique that tracks how information flows in a program. 

+ Sources 
  + locations where information flows into the program. 
    + `scanf()`, `getenv()`, and etc.
+ Sinks
  + locations where sensitive or untrustworthy information may introduce concerns. 
    + `send()`, `execve()`, `malloc()`, `strcpy()`, `/`, and etc 

---

# An Example

```c
int f()
{
    int a, b, c, num;
    printf("Enter an integer: ");
    scanf("%d", &num);
    a = num * 2; 
    b = a + 2 ;
    c = b - 6; 
    float result = 10.0 / c;
    printf("Result: %.2f\n", result);
}
```

---

# Security Applications

+ Detecting Vulnerabilities
  + Buffer/Heap Overflows
  + Remote Code Execution
  + Divide by 0
  + Information Leakage
+ Malware Analysis
  + Information Exfiltration
  + API-Dependency Analysis

---
# Analysis Strategies

+ Forward Analysis
  + to study how information propogates from sources to sinks. 
+ Backward Analysis
  + to study how to track information used in sinks back to its sources. 

---
# Dynamic Taint Analysis

Learn how information propogates in a program by executing it or elumating it.
+ Typically uses forward analysis.

---
# Dynamic Taint Analysis

Tools/Platforms:
+ Intel PIN
+ QEMU
+ Triton
+ Angr
+ ...

---
# Static Taint Analysis

Learn how information propogates in a program without executing it. 
+ Typically performs analysis on the abstraction of a program. 
+ Forward analysis, backward analysis, or both are used.  

---
# Static Taint Analysis

Tools/Platforms:
+ Clang
+ Many other tools
+ 
---
# Implementing A Static Taint Analyer with P-Code Using Ghidra

sources: built-in functions (i.e., thunk functions in Ghidra)
sink: division, specifically the denominator of the division
scope: intra-procedural process