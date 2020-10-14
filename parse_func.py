#coding:utf-8

import idc 
import idautils 
import idaapi 

'''
TODO: 主要用于参数识别，需要完善这个部分，然后加入到代码中
'''


start = idc.get_func_attr(here(),FUNCATTR_START)
end = idc.get_func_attr(here(), FUNCATTR_END)

curr_addr = start
stackSize = None

retValue = []
argValue = []

while curr_addr <= end:
    tmp = idaapi.insn_t()
    # print(hex(curr_addr),idc.GetDisasm(curr_addr))
    op = idc.print_insn_mnem(curr_addr)
    if stackSize is None:
        # 找 sub esp,value 指令
        # 获取当前栈帧的大小
        if op == "sub":
            firstOp = idc.print_operand(curr_addr,0)
            tmp = idaapi.insn_t()
            idaapi.decode_insn(tmp,curr_addr)
            if tmp.Op1.type == idc.o_reg and firstOp == "esp":
                stackSize = tmp.Op2.value
    else:
        if op == "mov":
            tmp = idaapi.insn_t()
            idaapi.decode_insn(tmp,curr_addr)
            firstOp = idc.print_operand(curr_addr,0)
            secondOp = idc.print_operand(curr_addr,1)
            if tmp.Op1.type == idc.o_reg and tmp.Op2.type == idc.o_displ and "[esp+" in secondOp :
                # 找 mov edx, [esp+160] 操作
                offset = tmp.Op2.addr 
                if offset > stackSize:
                    argValue.append( offset - stackSize )

            elif tmp.Op1.type == idc.o_displ and tmp.Op2.type == idc.o_reg and "[esp+" in firstOp:
                # 找 mov [esp+160], edx 
                offset = tmp.Op1.addr
                if offset > stackSize:
                    retValue.append( offset - stackSize )
        
    curr_addr = idc.next_head(curr_addr,end)
retValue = sorted(retValue,reverse=True)
argValue = sorted(argValue)


# 返回值一定是一段连续的栈偏移空间，如果出现不连续的值，那肯定不是返回值，需要删除

def getContinuesValueIndex(retValue):
    if len(retValue) == 0:
        return 0
    for index,value in enumerate(retValue):
        if value != retValue[0] - index *4 :
            # return index
            break
    return index+1

retValue = retValue[0:getContinuesValueIndex(retValue)]
retCount = len(retValue)
argCount = retValue[0] // 4 - retCount
print("[*] retValue {} .".format(retValue))
print("[*] argValue {} .".format(argValue))


print("[*] function name: {} , argcount is {} ,retcount is {}, input arg count is {}".format( 
    idc.get_func_name(start),argCount,retCount,argCount + retCount ))

def makeFunctionDef(name,argCount,retCount):
    functionDef = "void __cdecl {name}({inArg},{outArg})"
    inArg = ""
    outArg = ""

    for index in range(argCount):
        if index != 0:
            inArg += ","
        inArg += "int arg" + str(index+1) 
    for index in range(retCount):
        if index !=0:
            outArg += ","
        outArg += "int ret" + str(index+1)
    functionDef = functionDef.format(name=name,inArg=inArg,outArg=outArg)

    return functionDef

print("[*] Modify the function declaration.")
functionDef = makeFunctionDef( idc.get_func_name(start),argCount,retCount)
idc.SetType(start,functionDef)
idc.set_cmt(start,functionDef,1)

    



