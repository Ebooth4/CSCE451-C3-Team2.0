# Team 2.0: Joshua Wood, Michael Mirhosseini, Xiaohu Huang, Evan Graham

# ghidra imports
import ghidra
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.symbol import RefType, ReferenceManager, Reference
from ghidra.program.model.address import Address, AddressSpace
from ghidra.program.model.listing import VariableFilter
from ghidra.app.decompiler.component import DecompilerUtils
# graphing imports
import networkx as nx
import matplotlib.pyplot as plt
import random

# Set this to True to remove all functions with no variables (only show source code functions)
remove_empty_functions = False
filter_names = False

# Define the function names that you want to check
function_names = []

def filterName(name):
    if filter_names:
        name = name[:-1] # remove the v added to the end
        filter_strings = ['_Z1', '_Z2', '_Z3', '_Z4', '_Z5', '_Z6', '_Z7', '_Z8', '_Z9']
        for filter in filter_strings:
            name = name.replace(filter, '') # remove all strings to filter out
    return name

def getVars(fun):
    # following code (excluding return statement) taken from github: https://github.com/HackOvert/GhidraSnippets#program-slices
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    res = ifc.decompileFunction(fun, 60, monitor)
    high = res.getHighFunction()
    return list(high.getLocalSymbolMap().getNameToSymbolMap().values())

def createFunctionCallData(root):
    def isFunctionEmpty(fun):
        return len(fun.getLocalVariables()) == 0 and remove_empty_functions
    dependencies = [] # a list of tuples showing what calls each function makes
    futureNodes = [root] # a list of functions to look at

    # breadth first search of all functions in the program starting at main
    while len(futureNodes) > 0:
        thisNode = getFunction(futureNodes.pop()) # take the first function from the beginning of the list
        if isFunctionEmpty(thisNode):
            continue # don't look at this function if it is empty
        thisNodeName = str(thisNode.getName())
        if thisNodeName in function_names:
            continue
        else:
            function_names.append(thisNodeName) # add to the global list of function names

        for child in thisNode.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY): # for every call this function makes
            if isFunctionEmpty(child):
                continue # don't look at the called function if it is empty
            childName = str(child.getName())
            dependency = (filterName(thisNodeName), filterName(childName)) # create a tuple from the current function to the called function
            dependencies.append(dependency) # add this tuple to the list
            if not child in futureNodes and thisNodeName != childName:
                futureNodes.append(child.getName()) # add the child node to the list of nodes to check in the future
    return ("Map of Function Calls", dependencies)

def createVariableUseData(function_name):
    # Get the function object
    function = getFunction(function_name)

    # Get the local variables of the function
    local_vars = getVars(function)
    # if len(local_vars) == 0:
    #     print("This function has no variables.")

    function_dependencies = [] # list of tuples to graph

    # Loop through each local variable
    for local_var in local_vars:
        instances = local_var.getHighVariable().getInstances()
        # create a list of variables in the lines where this variable is mentioned
        instance_vars = []
        for instance in instances:
            if instance.getLoneDescend() is None:
                continue
            if instance.getLoneDescend().getOutput() is None:
                continue
            instance_vars.append(str(instance.getLoneDescend().getOutput().getHigh().getName()))
            for line_input in instance.getLoneDescend().getInputs():
                if line_input.getHigh() is None:
                    continue
                instance_vars.append(str(line_input.getHigh().getName()))
        # look through list for dependencies
        this_var = str(local_var.getName())
        for that_var in instance_vars:
            if this_var is not that_var and not (this_var, that_var) in function_dependencies and that_var is not None:
                function_dependencies.append((this_var, that_var))
    return (filterName(function_name), function_dependencies)

def getDependencies():
    all_dependencies = [createFunctionCallData("main")]
    for function_name in function_names:
        all_dependencies.append(createVariableUseData(function_name))
    return all_dependencies

def make_graph(input_list_and_title, side_length = 15, top_length = 15, save_file = False, show_graph = True) :

    """
    make_graph():
            Creates a graph based on given edges
    
    input_list_and_title:
            This parameter should be a tuple containing the title 
            desired for the window / file name and a list of tuples 
            containing edges for the graph

            E.X. ("Title", [(A, B), (B, C), (C, D)])

    side_length:
            top to bottom length of the pop up window displaying 
            the graph in inches. Default is 15

    top_length:
            left to right length of the pop up window displaying 
            the graph in inches. Default is 15

    save_file:
            Boolean value to determine whether or not the graph 
            will be saved to a png with the file name the same as the title
            Default is False

    show_graph:
            Boolean value to determine if the pop up window 
            containing the graph will show or not.
            Default is True

    """

    G=nx.DiGraph() # Create initial graph with networkx

    ###########################################
    #               Input List
    ###########################################

    # parameter is a list that contains tuples regarding relationships between nodes
    title, input_list = input_list_and_title

    ###########################################
    #               Plt Formating
    ###########################################

    # Creating the plot (I.E. sizing and formatting)
    plt.figure(title, figsize=(side_length, top_length)).subplots_adjust(left=0,right=1,top=1,bottom=0)
    ax=plt.axes()
    ax.set_facecolor("black")

    ###########################################
    #           Seed Generation
    ###########################################

    # seed = random.randrange(50000) # rand number to test different formats
    # print(seed)

    seed = 1105
    # 1105 - Good seed

    ###########################################
    #               Graphing
    ###########################################

    G.add_edges_from(input_list) # Function to create edges from the inputted list (from above)

    pos = nx.spring_layout(G, seed=seed) # Creating the position vaiable to ensure every node, edge, and label lines up
    node_sizes = [len(i) * 200 for i in G.nodes()] # Scaling node based on label size (not perfect)

    nx.draw_networkx_labels(G, pos, font_color="white", font_size="10") # Create labels for the nodes
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes) # Place the nodes with those labels
    nx.draw_networkx_edges(G,
                        pos,
                        arrowstyle="->",   
                        arrows=True,
                        arrowsize=20,
                        edge_color="white",
                        node_size=node_sizes,
                        width=2) # Attach edges to each node

    ############################################
    #               Show Graph
    ############################################

    ax.axis('tight') # Removes white border
    if (save_file):
        plt.savefig(title + ".png") # Save plot to an image
    if (show_graph):
        plt.show() # Create pop up to diplay the graph

dependencies = getDependencies()
print(dependencies)
for this_graph in dependencies:
    if len(this_graph[1]) > 0:
        make_graph(this_graph, save_file = True)

# def getConditionalAsNode():

#     # get the current program
#     program = state.getCurrentProgram()

#     # get the current function
#     function = getFunctionContaining(currentAddress)

#     # get the listing for the current function
#     listing = program.getListing()
#     instructions = listing.getInstructions(function.getEntryPoint(), True)

#     # iterate through the instructions and look for if-else statements
#     for instruction in instructions:
#         if instruction.getFlowType().isConditional():
#             # get the conditional expression
#             conditional = instruction.getBranchSource(0).toString()
#             # just for testing
#             print("Conditional expression: " + conditional)
# getConditionalAsNode()