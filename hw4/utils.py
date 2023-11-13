def convBytes(data):
    return int.from_bytes(data, byteorder='little')

def convBits(data):
    return int(data, 2)

def getRvcRegister(val):
    if val <= 1:
        return 's' + str(val)
    else:
        return 'a' + str(val - 2)

def getSlice(val, start, end): 
    return (val >> start) & ((1 << (end - start + 1)) - 1)

def calcImm(val, end, start, last):
    return getSlice(val,last - (end - start),last) << (start)

def getRegister(val):
    if val == 0:
        return "zero"
    elif val == 1:
        return "ra"
    elif val == 2:
        return "sp"
    elif val == 3:
        return "gp"
    elif val == 4:
        return "tp"
    elif 5 <= val <= 7:
        return "t" + str(val - 5)
    elif val == 8:
        return "s0"
    elif val == 9:
        return "s1"
    elif 10 <= val <= 17:
        return "a" + str(val - 10)
    elif 18 <= val <= 27:
        return "s" + str(val - 16)
    elif 28 <= val <= 31:
        return "t" + str(val - 25)