from utils import *
from enum import Enum

class RV32type(Enum):
    Rtype = 0,
    Itype = 1,
    Stype = 2,
    Btype = 3,
    Utype = 4,
    Jtype = 5

def parseRtype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6) 
    result['rd'] = getRegister(getSlice(data, 7, 11) )
    result['funct3'] =  getSlice(data, 12, 14) 
    result['rs1'] =  getRegister(getSlice(data, 15, 19) )
    result['rs2'] =  getRegister(getSlice(data, 20, 24) )
    result['funct7'] =  getSlice(data, 25, 31) 
    return result

def parseItype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6)
    result['rd'] = getRegister(getSlice(data, 7, 11) )
    result['funct3'] =  getSlice(data, 12, 14) 
    result['rs1'] =  getRegister(getSlice(data, 15, 19) )
    result['uimm'] =  getSlice(data, 20, 31) 
    result['imm'] =  calcImm(data, 11, 0, 31)
    if getSlice(data, 31, 31):
        result['imm'] -= (1 << 12)
    return result

def parseStype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6)
    result['funct3'] =  getSlice(data, 12, 14) 
    result['rs1'] =  getRegister(getSlice(data, 15, 19) )
    result['rs2'] =  getRegister(getSlice(data, 20, 24) )
    result['imm'] =  calcImm(data, 11, 5, 31) | calcImm(data, 4, 0, 11)
    if getSlice(data, 31, 31):
        result['imm'] -= (1 << 12)
    return result

def parseBtype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6)
    result['imm'] = calcImm(data, 12, 12, 31) | calcImm(data, 10, 5, 30) | calcImm(data, 4, 1, 11) | calcImm(data, 11, 11, 7)
    result['funct3'] =  getSlice(data, 12, 14) 
    result['rs1'] =  getRegister(getSlice(data, 15, 19) )
    result['rs2'] =  getRegister(getSlice(data, 20, 24) )
    if getSlice(data, 31, 31):
        result['imm'] -= (1 << 13)
    return result


def parseUtype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6)
    result['rd'] = getRegister(getSlice(data, 7, 11))
    result['imm'] =  calcImm(data, 31, 12, 31)
    if getSlice(data, 31, 31):
        result['imm'] -= (1 << 32)
    return result

def parseJtype(data):
    result = {}
    result['opcode'] = getSlice(data, 0, 6)
    result['rd'] =  getRegister(getSlice(data, 7, 11))
    result['imm'] = calcImm(data, 20, 20, 31) | calcImm(data, 10, 1, 30) | calcImm(data, 11, 11, 20) | calcImm(data, 19, 12, 19)
    if getSlice(data, 31, 31):
        result['imm'] -= (1 << 21)
    return result

typeByOpcode = {
    0b0110111 : RV32type.Utype,
    0b0010111 : RV32type.Utype,
    0b1101111 : RV32type.Jtype,
    0b1100111 : RV32type.Itype,
    0b1100011 : RV32type.Btype,
    0b0000011 : RV32type.Itype,
    0b0100011 : RV32type.Stype,
    0b0010011 : RV32type.Itype,
    0b0110011 : RV32type.Rtype,
    0b0001111 : RV32type.Btype,
    0b1110011 : RV32type.Itype,
    0b1110011 : RV32type.Itype
}

typeToParser = {
    RV32type.Rtype : parseRtype,
    RV32type.Itype : parseItype,
    RV32type.Stype : parseStype,
    RV32type.Btype : parseBtype,
    RV32type.Utype : parseUtype,
    RV32type.Jtype : parseJtype,
}
