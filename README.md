# ALIEN: idA Local varIables(or inLine functIons) rEcogNizer
`ALIEN` is an IDA Pro plugin that allows the user to get more information about ida local variables and inline functions with the help of corresponding `DWARF` information.

## Usage
```
python3 dwarf_parser.py <path_of_the_ELF>
```
This script will analysis the DWARF information of the given ELF file, and will produce `.dwarf.json` file contains the analytical result in the same folder.
```
<path_of_idat/idat64> -A -c -S"ida_parse_f5.py" <path_of_the_ELF>
```
This IDA-python script will produce `.ida.json` file contains the analytical result of IDA in the same folder.
```
python3 module_analysis.py <path_of_the_ELF>
```
If you run the first two steps and successfully get `.dwarf.json` as well as `.ida.json` file, then this `module_analysis.py` script will perform comprehensive analysis of these two. The result will be stored in `.ans.json` file.

This is an example of the `.ans.json` file:
```
{
    "ModuleInfo": {
        "ida_num_total": 4815,
        "ida_none_num_total": 346,
        "ida_has_dwarf_total": 337,
        "ida_reg_num_total": 4261,
        "ida_stack_num_total": 553,
        "inlined_num": 584,
        "declared_inline_num": 22,
        "has_inlinee_num": 650,
        "dwarf_num_total": 2118,
        "dwarf_none_num_total": 584,
        "dwarf_reg_num_total": 992,
        "dwarf_stack_num_total": 254,
        "dwarf_poly_num_total": 224,
        "dwarf_unknown_num_total": 64,
        "ans_ida_identified_num_total": 296
    },
    "FunctionInfo": [
        {
            "func_name": "js_stackoverflow",
            "ida_num": 2,
            "ida_none_num": 0,
            "ida_has_dwarf": 0,
            "ida_reg_num": 2,
            "ida_stack_num": 0,
            "dwarf_num": 0,
            "dwarf_none_num": 0,
            "dwarf_reg_num": 0,
            "dwarf_stack_num": 0,
            "dwarf_poly_num": 0,
            "dwarf_unknown_num": 0,
            "ans_ida_identified_num": 0
        },
    ···
    ]
}
```
