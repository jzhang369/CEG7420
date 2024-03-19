# This is a simple script to dump the refined pcode.  
# @category: CEG7420.Demo
# @author: Junjie Zhang

#from ghidra.app.decompiler import *
#from ghidra.app.script.GhidraScript import *
from ghidra.program.model.block import BasicBlockModel
#from ghidra.util.graph.DirectedGraph import DirectedGraph
from ghidra.util.graph import DirectedGraph 
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
from ghidra.service.graph import GraphDisplay

#plist = currentProgram.getListing()
func = getFunctionContaining(currentAddress)
blockModel = BasicBlockModel(currentProgram)

cfg = DirectedGraph()

num_bb = 0
node_set = set()
edge_set = set()

if func is None:
    print("No function is found at this address")
elif blockModel is None:
    print("No basic block model is generated for this function")
else:
    print("Enumerate basic blocks")
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
    for block in blocks:
        num_bb = num_bb + 1
        if (block not in node_set()):
            node_set.add(block)
            from_node = Vertex(block)
            cfg.add(from_node)
            successors = block.getDestinations(monitor)
            while successors.hasNext():
                i = successors.next()
                if (i not in node_set()):
                    node_set.add(i)
                    to_node = Vertex(i)
                    edge = Edge(from_node, to_node)
                    if edge not in edge_set():
                        edge_set.add(edge)
                        cfg.add(edge)

    print("Number of Basic Blocks: ", num_bb)
    print("Number of Nodes: ", cfg.numVertices())
    print("Number of Edges: ", cfg.numEdges())
