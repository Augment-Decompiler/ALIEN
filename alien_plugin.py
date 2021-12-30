# -*- coding:utf-8 -*-

# ========================import============================ #
import idaapi
import idautils
import idc
import os
import json
import dwarf_parser


'''
ea:         the address of the code(EX: 0x1737)
comment:    the comment at the ea address(EX: "this is a comment")

set the comment at the specific address, as a prefix
'''
def set_comment_pre(ea, comment):
    pre_comment = idc.get_cmt(ea, False)
    if(pre_comment == None):
        pre_comment = ""
    idc.set_cmt(ea, comment + pre_comment, False)


'''
ea:         the address of the code(EX: 0x1737)
color:      the background color you want at the ea address(EX: 0xffffffff)
set the background color at the specific address
'''
def set_color(ea, color):
    idaapi.set_item_color(ea, color)



'''
lists:          the lists of the range [[x,y], ....]
range_info:     the range [x1, y1]

return the idx of the overlap range with range_info in lists, or return the where is should be inserted to keep the monotonically increase

the the overlap situation can only be
lists[i][0] < lists[i][1] + 1 == x1 < y1

or

x1 < y1 <= lists[i][0] - 1 < lists[i][1]
'''
def get_overlap_idx(lists, range_info):
    if(len(lists) == 0):
        return 0
    
    '''
    assumed that lists[0][0] <= lists[0][1] <= lists[1][0] <= lists[1][1] <= ...
    we can use bsearch
    '''

    left = 0
    right = len(lists) - 1

    while(left <= right):
        middle = left + (right - left) // 2
        if(lists[middle][1] == (range_info[0] - 1) or (range_info[1] + 1) == lists[middle][0]):
            return middle
        elif(range_info[0] > lists[middle][1]):
            left = middle + 1
        else:
            right = middle - 1

    return left

'''
the handler class
it resigter the plugin in **Edit** menu in ida, instead of register in the **Edit/Plugins** 
'''
class AlienHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    '''
    plugin argument is the class instance of ALIEN defined below
    '''
    @classmethod
    def register(self, plugin):
        self.plugin = plugin
        self.label = plugin.wanted_name
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            plugin.wanted_name,  # Name. Acts as an ID. Must be unique.
            plugin.wanted_name,  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())


    '''
    when the plugin is active/invoked
    then should call activate
    '''
    def activate(self, ctx):
        self.plugin.run()
        return 1
    

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


'''
callback class

it will be invoked by ida, to initial、register the plugin, as well as the callback for the plugin

it will call `init` to initial the plugin at first
it will call `run` when the plugin in menu is clicked
it will call `term` to destruct the plugin
'''
class ALIEN(idaapi.plugin_t):

    '''
    plugin attribute
    '''
    wanted_hotkey = "Ctrl-Alt-A"    # the hot key
    comment = "comment [TODO]"
    help = "help [TODO]"
    flags = idaapi.PLUGIN_KEEP      # the type/life-cycle of the plugin
    wanted_name = "Alien"           # This is the plugin name in the ida menu
    version = "v1.0"

    data = None                     #the function, its attribute and its address space
    color_list = [0x7fffd4, 0xffffe0, 0xadd8e6, 0xf0fff0, 0xd3d3d3, 0xd8bfd8]


    def init(self):


        '''register the action for the plugin'''
        AlienHandler.register(self)

        '''register the menu'''
        idaapi.attach_action_to_menu(
           'Edit/Plugins',
           self.wanted_name,
           idaapi.SETMENU_APP)


        '''
        try to load the *.dwarf.json in the same directory
        '''
        json_path = os.path.join(idautils.GetIdbDir(), idaapi.get_root_filename() + '.dwarf.json')

        if not os.path.exists(json_path):
            file_name = os.path.join(idautils.GetIdbDir(), idaapi.get_root_filename())
            with open(json_path, 'w+') as f:
                dwarf_parser.json.dump(dwarf_parser.process_file(file_name),f)

        with open(json_path, 'r') as f:
            self.data = json.loads(''.join(f.readlines()))


        '''
            the log in output window
            when the IDAPython initial the Plugin
        '''
        print('================================================================================')
        print('Alien ' + self.version + ' (c) Augment-Decompiler, 2021')
        print('Alien\'s shortcut key is ' + self.wanted_hotkey)
        print('Please check the Edit/Plugins menu for more information')
        print('================================================================================')


        return idaapi.PLUGIN_KEEP
    
    
    def run(self, arg = None):
        print('================================================================================')
        '''
        set the background color due to the data member
        '''
        if(self.data != None):

            for function_info in self.data["FunctionInfo"]:

                if("inlinee_list" in function_info):
                    '''
                    set the adjacent range with same color
                    so use {name:[[x, y]], ...} to record the range
                    it will merge the adjacent range
                    '''
                    dics = {}

                    for inlinee_info in function_info["inlinee_list"]:
                        if("ranges" in inlinee_info):
                            for idx in range(len(inlinee_info["ranges"])):
                                range_info = [int(inlinee_info["ranges"][idx][0], 16), int(inlinee_info["ranges"][idx][1], 16) - 1]
                                #print('initial ' + inlinee_info['name'] + '-range_info: [' + hex(range_info[0]) + ', ' + hex(range_info[1]) + ']')

                                # merge the adjacent range
                                if(inlinee_info['name'] not in dics):
                                    dics[inlinee_info['name']] = []

                                overlap_idx = get_overlap_idx(dics[inlinee_info['name']], range_info)
                                if(overlap_idx == len(dics[inlinee_info['name']])):
                                    dics[inlinee_info['name']].append([range_info[0], range_info[1]])
                                elif(overlap_idx + 1 < len(dics[inlinee_info['name']]) and dics[inlinee_info['name']][overlap_idx][1] == (range_info[0] - 1) and dics[inlinee_info['name']][overlap_idx + 1][0] == (range_info[1] + 1)):
                                    dics[inlinee_info['name']][overlap_idx][1] = dics[inlinee_info['name']][overlap_idx][1]
                                    del dics[inlinee_info['name']][overlap_idx + 1]
                                elif(overlap_idx - 1 >= 0 and dics[inlinee_info['name']][overlap_idx - 1][1] == (range_info[0] - 1) and dics[inlinee_info['name']][overlap_idx][0] == (range_info[1] + 1)):
                                    dics[inlinee_info['name']][overlap_idx - 1][1] = dics[inlinee_info['name']][overlap_idx][1]
                                    del dics[inlinee_info['name']][overlap_idx]
                                elif(dics[inlinee_info['name']][overlap_idx][1] == (range_info[0] - 1)):
                                    dics[inlinee_info['name']][overlap_idx][1] = range_info[1]
                                elif(dics[inlinee_info['name']][overlap_idx][0] == (range_info[1] + 1)):
                                    dics[inlinee_info['name']][overlap_idx][0] = range_info[0]
                                else:
                                    dics[inlinee_info['name']].insert(overlap_idx, [range_info[0], range_info[1]])


                                #print('comment ' + inlinee_info['name'] + '-range_info: [' + hex(range_info[0]) + ', ' + hex(range_info[1]) + ']')

                                #set the end label
                                if(idx == len(inlinee_info["ranges"]) - 2):
                                    set_comment_pre(range_info[0], "End-Inlinee: " + inlinee_info["name"] + '\n')
                                    continue

                                if idx == 0:
                                    set_comment_pre(range_info[0], "Begin-Inlinee: " + inlinee_info["name"] + '\n')
                                    continue

                                set_comment_pre(range_info[0], "Inlinee: " + inlinee_info["name"] + '\n')

                                

                    #set the color
                    for key in dics.keys():
                        for i in range(len(dics[key])):
                            #print('color ' + key + '-range_info: [' + hex(dics[key][i][0]) + ', ' + hex(dics[key][i][1]) + ']' + ' ' + str(self.color_list[i % len(self.color_list)]))
                            for ea in range(dics[key][i][0], dics[key][i][1]):
                                set_color(ea, self.color_list[i % len(self.color_list)])
        
        print("Alien: finish analysis")
        print('================================================================================')

    def term(self):
        return None


def PLUGIN_ENTRY():
    '''
    instantiate the class 
    '''
    return ALIEN()