# graphing imports
import networkx as nx
import matplotlib.pyplot as plt
import random

# change this variable here:
dependencies = [('Map of Function Calls', [('main', '_Z9function1ii'), ('main', '__main'), ('main', '_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc'), ('main', '_ZNSolsEi'), ('main', '_ZNSolsEPFRSoS_E'), ('main', '_Z9function2ii'), ('_Z9function2ii', '_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc'), ('_Z9function2ii', '_ZNSolsEi'), ('_Z9function2ii', '_ZNSolsEPFRSoS_E'), ('_ZNSolsEPFRSoS_E', '_ZNSolsEPFRSoS_E'), ('_ZNSolsEi', '_ZNSolsEi'), ('_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc', '_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc'), ('__main', '__do_global_ctors'), ('__do_global_ctors', 'atexit'), ('atexit', '_onexit'), ('_onexit', '_crt_atexit'), ('_crt_atexit', '_crt_atexit'), ('_Z9function1ii', '_Znwy'), ('_Z9function1ii', '_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc'), ('_Z9function1ii', '_ZNSolsEi'), ('_Z9function1ii', '_ZNSolsEPFRSoS_E'), ('_Znwy', '_Znwy')]), ('main', [('iVar1', 'uVar2'), ('iVar1', 'iVar1'), ('uVar2', 'uVar2'), ('uVar2', 'iVar1')]), ('_Z9function2ii', [('param_1', 'UNNAMED'), ('param_1', 'param_2'), ('param_1', 'param_1'), ('param_2', 'UNNAMED'), ('param_2', 'param_2'), ('param_2', 'param_1'), ('uVar1', 'uVar1'), ('uVar1', 'None')]), ('_ZNSolsEPFRSoS_E', []), ('_ZNSolsEi', []), ('_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc', []), ('__main', []), ('__do_global_ctors', [('ppcVar4', 'ppcVar4'), ('uVar2', 'uVar2'), ('uVar2', 'uVar3')]), ('atexit', [('p_Var1', 'UNNAMED'), ('p_Var1', 'p_Var1'), ('p_Var1', 'None'), ('param_1', 'UNNAMED'), ('param_1', 'param_1')]), ('_onexit', [('_Func', 'p_Var2'), ('_Func', '_Func'), ('iVar1', 'UNNAMED'), ('iVar1', 'iVar1'), ('iVar1', 'None'), ('p_Var2', 'p_Var2')]), ('_crt_atexit', []), ('_Z9function1ii', [('param_1', 'UNNAMED'), ('param_1', 'param_2'), ('param_1', 'param_1'), ('param_2', 'UNNAMED'), ('param_2', 'param_2'), ('param_2', 'param_1'), ('uVar5', 'uVar5'), ('uVar5', 'UNNAMED')]), ('_Znwy', [])]

import networkx as nx
import matplotlib.pyplot as plt
import random


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
    node_sizes = 6000

    nx.draw_networkx_labels(G, pos, font_color="white", font_size="15") # Create labels for the nodes
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

for this_graph in dependencies:
    if len(this_graph[1]) > 0:
        make_graph(this_graph, save_file=True)