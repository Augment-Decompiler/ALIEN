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

set the comment at the specific address
'''
def set_comment(ea, comment):
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
the handler class

just a handler when the plugin is invoked
provide with nothing, just a class followed with the IDA authority
'''
class AlienHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    '''
    when the plugin is active/invoked
    then should call activate
    '''
    def activate(self, ctx):
        return 1
    
    def update(self, ctx):
        return idaapi.AST_DISABLE


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
    colir_list = [0x7fffd4, 0xffffe0, 0xadd8e6, 0xf0fff0, 0xd3d3d3, 0xd8bfd8]
    color_idx = 0


    def init(self):


        '''register the action for the plugin'''
        idaapi.register_action(idaapi.action_desc_t(
           "plugin:Alien",     #the action name, shouble be unique for the plugin
           self.wanted_name,    #the action show text
           AlienHandler(),     #the action handler
        ))


        '''register the menu'''
        idaapi.attach_action_to_menu(
           'Edit/Plugins',
           'plugin:Alien',
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


        return self.flags
        
    
    def run(self, arg):
        print('================================================================================')
        '''
        set the background color due to the data member
        '''
        if(self.data != None):

            sets = set()
            for function_info in self.data["FunctionInfo"]:
                if("inlinee_list" in function_info):
                    for inlinee_info in function_info["inlinee_list"]:
                        if("ranges" in inlinee_info):
                            for idx in range(len(inlinee_info["ranges"])):
                                range_info = [int(inlinee_info["ranges"][idx][0], 16), int(inlinee_info["ranges"][idx][1], 16)]

                                #avoid overwrite
                                if(range_info[0] in sets):
                                    range_info[0] = range_info[0] - 1
                                
                                if(range_info[1] in sets):
                                    range_info[1] = range_info[1] - 1
                                sets.add(range_info[0])
                                sets.add(range_info[1])

                                #set the end label
                                if idx == len(inlinee_info["ranges"]) - 1:
                                    set_comment(range_info[1], "\nEnd-inlinee: " + inlinee_info["name"])

                                #set name label
                                set_comment(range_info[0], 'inlinee: ' + inlinee_info["name"] + '\n')

                                #set the begin label
                                if idx == 0:
                                    set_comment(range_info[0], 'Begin-Inlinee: ')


                                # set the color
                                for ea in range(range_info[0], range_info[1] + 1):
                                    set_color(ea, self.colir_list[self.color_idx])
                                
                                print(inlinee_info["name"] + " [" + hex(range_info[0]) + ", " + hex(range_info[1]) + "]")

                            self.color_idx = (self.color_idx + 1) % len(self.colir_list)
        
        print("Alien: finish analysis")
        print('================================================================================')

    def term(self):
        return None


def PLUGIN_ENTRY():
    '''
    instantiate the class 
    '''
    return ALIEN()