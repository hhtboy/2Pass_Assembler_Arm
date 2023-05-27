import sys
import re
import math

cond = {'eq': 0, 'ne': 1, 'hs': 2, 'cs': 2, 'lo': 3,
        'cc': 3, 'mi': 4, 'pl': 5, 'vs': 6, 'vc': 7,
        'hi': 8, 'ls': 9, 'ge': 10, 'lt': 11, 'gt': 12,
        'le': 13, 'al': 14, 'nv': 15}

registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4,
             'r5': 5, 'r6': 6, 'r7': 7, 'r8': 8, 'r9': 9,
             'r10': 10, 'r11': 11, 'r12': 12, 'r13': 13,
             'r14': 14, 'r15': 15, 'sl': 10, 'fp': 11,
             'ip': 12, 'sp': 13, 'lr': 14, 'pc': 15}

def make_regexp(li):
    res = '('
    for elem in li:
        res += elem + '|'
    res = res.rstrip('|')
    res += ')'
    return res

cond_regexp = make_regexp(cond.keys())

def process_cond_field(mach_code, tok):
    cond_field = tok[:2]
    if cond_field in cond:
        mach_code |= cond[cond_field] << 28
        tok = tok[2:]
    else:
        mach_code |= 14 << 28
    return (mach_code, tok)

def process_S_flag(mach_code, tok):
    if tok == 's':
        mach_code |= 1 << 20
        tok = tok[1:]
    return (mach_code, tok)

def process_2_args(mach_code, args, opcode):

    if opcode == "swi":
        try:
            swi_num = int(args[0])
            mach_code |= swi_num
            return mach_code
        except:
            sys.exit(1)

    if opcode == "mul":
        if len(args) == 3:
            if args[0] in registers and args[2] in registers:
                mach_code |= registers[args[0]] << 16 
                mach_code |= registers[args[2]] 
                mach_code |= registers[args[0]] << 8 

                return mach_code
            else:
                sys.exit(1)

        elif len(args) == 5:
            if args[0] in registers and args[2] in registers and args[4] in registers:
                mach_code |= registers[args[0]] << 16 
                mach_code |= registers[args[2]] 
                mach_code |= registers[args[4]] << 8 

                return mach_code
            else:
                sys.exit(1)


        else:
            sys.exit(1)

    if opcode == "mla":
        if len(args) == 7:
            if args[0] in registers and args[2] in registers and args[4] in registers and args[6] in registers:
                mach_code |= registers[args[0]] << 16 
                mach_code |= registers[args[2]] 
                mach_code |= registers[args[4]] << 8
                mach_code |= registers[args[6]] << 12

                return mach_code
            else:
                sys.exit(1)
        else:
            sys.exit(1)


        

    if args[0] in registers:
            mach_code |= registers[args[0]] << 12
    
    else: 
            sys.exit(1)

    if args[1] != ',':
            sys.exit(1)

    if len(args) == 3:
        if opcode in ["mov", "mvn", "add", "sub", "rsb", "eor"]:
            if opcode in ["add", "sub", "rsb", "eor"]:
                mach_code |= registers[args[0]] << 16
                
            if args[2] in registers:
                mach_code |= registers[args[2]]
            elif args[2][0] == '#': 
                mach_code |= 0b0010 << 24 
                args[2] = args[2][1:]
                if int(args[2]) >= 256:
                    mach_code |= rotateIm(args[2])
                else:
                    mach_code |= int(args[2])

            else: 
                sys.exit(1)
        else:
            sys.exit(1)

    elif len(args) == 5:
        if opcode in ["add", "sub", "rsb", "eor"]:
            if args[3] != ',':
                sys.exit(1)
            if args[2] in registers: 
                mach_code |= registers[args[2]] << 16
            else: 
                sys.exit(1)

            if args[4] in registers:
                mach_code |= registers[args[4]]
            elif args[4][0] == "#":
                mach_code |= 0b0010 << 24 
                args[4] = args[4][1:]
                if int(args[4]) >= 256:
                    mach_code |= rotateIm(args[4])
                else:
                    mach_code |= int(args[4])
            else:
                sys.exit(1)
                
        else:
            sys.exit(1)
            

    elif len(args) == 6:
        if opcode in ["mov", "mvn", "add", "sub", "rsb", "eor"]:
            if opcode in ["add", "sub", "rsb", "eor"]:
                mach_code |= registers[args[0]] << 16
                
            if args[3] != ',':
                sys.exit(1)
            if args[2] in registers:
                mach_code |= int(registers[args[2]])

                if args[4] == "lsl":
                    mach_code |= 0b00 << 5
                elif args[4] == "lsr":
                    mach_code |= 0b01 << 5
                elif args[4] == "asr":
                    mach_code |= 0b10 << 5
                elif args[4] == "ror":
                    mach_code |= 0b11 << 5
                else:
                    sys.exit(1)

                if args[5] in registers:
                    mach_code |= registers[args[5]] << 8
                    mach_code |= 0b1 << 4

                elif args[5][0] != "#":
                    sys.exit(1)
                    
                else:
                    args[5] = args[5][1:]
                    if int(args[5]) > 32 or int(args[5]) < 0 :
                        sys.exit(1)
                    
                    mach_code |= int(args[5]) << 7
            else: 
                sys.exit(1)

        else:
            sys.exit(1)


    elif len(args) == 8:
        if opcode in ["add", "sub", "rsb", "eor"]:
            if args[1] != "," or args[3] != "," or args[5] != ",":
                sys.exit(1)

            if args[0] not in registers or args[2] not in registers or args[4] not in registers:
                sys.exit(1)

            mach_code |= registers[args[0]] << 12 
            mach_code |= registers[args[2]] << 16 
            mach_code |= registers[args[4]] 
            
            if args[6] == "lsl":
                mach_code |= 0b00 << 5
            elif args[6] == "lsr":
                mach_code |= 0b01 << 5
            elif args[6] == "asr":
                mach_code |= 0b10 << 5
            elif args[6] == "ror":
                mach_code |= 0b11 << 5
            else:
                sys.exit(1) 

            if args[7] in registers:
                mach_code |= registers[args[7]] << 8
                mach_code |= 0b1 << 4

            elif args[7][0] == "#":
                args[7] = args[7][1:]
                if int(args[7]) >= 0 and int(args[7]) < 32:
                   mach_code |= int(args[7]) << 7
                else:
                    sys.exit(1)  
            else:
                sys.exit(1)  
                
        else:
            sys.exit(1)

    return mach_code

def process_instruction(tokens, line_count):
    cur_opcode = None
    mach_code = 0
    tok = tokens[0]
    args = tokens[1:]

    mov_re = 'mov' + cond_regexp + '?' + 's' + '?'
    mvn_re = 'mvn' + cond_regexp + '?' + 's' + '?'
    add_re = 'add' + cond_regexp + '?' + 's' + '?'
    sub_re = 'sub' + cond_regexp + '?' + 's' + '?'
    rsb_re = 'rsb' + cond_regexp + '?' + 's' + '?'
    eor_re = 'eor' + cond_regexp + '?' + 's' + '?'
    swi_re = 'swi' + cond_regexp + '?' + 's' + '?'
    mul_re = 'mul' + cond_regexp + '?' + 's' + '?'
    mla_re = 'mla' + cond_regexp + '?' + 's' + '?'
    b_re = 'b' +'l' + '?' + cond_regexp + '?' + 's' + '?'
    ldr_re = 'ldr' + cond_regexp + '?' + 's' + '?'
    adr_re = 'adr' + cond_regexp + '?' + 's' + '?'

    if re.match(mov_re, tok):
        mach_code = 0b1101 << 21
        tok = tok[3:]
        cur_opcode = "mov"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    if re.match(mvn_re, tok):
        mach_code = 0b1111 << 21
        tok = tok[3:]
        cur_opcode = "mvn"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(add_re, tok):
        mach_code = 0b0100 << 21
        tok = tok[3:]
        cur_opcode = "add"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(sub_re, tok):
        mach_code = 0b0010 << 21
        tok = tok[3:]
        cur_opcode = "sub"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(rsb_re, tok):
        mach_code = 0b0011 << 21
        tok = tok[3:]
        cur_opcode = "rsb"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(eor_re, tok):
        mach_code = 0b0001 << 21
        tok = tok[3:]
        cur_opcode = "eor"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(swi_re, tok):
        mach_code |= 0b1111 << 24
        tok = tok[3:]
        cur_opcode = "swi"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(mul_re, tok):
        mach_code |= 0b1001 << 4
        tok = tok[3:]
        cur_opcode = "mul"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(mla_re, tok):
        mach_code |= 0b1001 << 4
        mach_code |= 0b1 << 21
        tok = tok[3:]
        cur_opcode = "mla"

        (mach_code, tok) = process_cond_field(mach_code, tok)
        (mach_code, tok) = process_S_flag(mach_code, tok)
        mach_code = process_2_args(mach_code, args, cur_opcode)

    elif re.match(b_re, tok):
        mach_code |= 0b101 << 25
        if tok == "bl":
            mach_code |= 0b1 << 24
        
        (mach_code, tok) = process_cond_field(mach_code, tok)
        two_pass_line.append((tokens, line_count))

    elif re.match(ldr_re, tok):
        isEmm = False
        num = 0
        try:
            if str(tokens[3]).startswith("=0x") or str(tokens[3]).startswith("=-0x"):
                num = int(str(tokens[3]).lstrip("="), 16)
                isEmm = True
            else:
                num = int(str(tokens[3]).lstrip("="))
                isEmm = True
            if num >= 256 :
                rot = rotateIm(num)
            else:
                rot = num

            if num < 0:
                mach_code |= 0b01010001 << 20 
                data_symbol_table[num] = num
                (mach_code, tok) = process_cond_field(mach_code, tok)
                two_pass_line.append((tokens, line_count))

            else:
                (mach_code, tok) = process_cond_field(mach_code, tok)
                data_symbol_table[num] = num
                mach_code |= 0b00111010 << 20
                mach_code |= registers[tokens[1]] << 12
                mach_code |= rot
            
            
        except:
            if isEmm:
                mach_code |= 0b01010001 << 20 
                data_symbol_table[num] = num
                (mach_code, tok) = process_cond_field(mach_code, tok)
                two_pass_line.append((tokens, line_count))
                
            else:
                mach_code |= 0b01010001 << 20 
                (mach_code, tok) = process_cond_field(mach_code, tok)
                two_pass_line.append((tokens, line_count))

    elif re.match(adr_re, tok):
        mach_code = 0
        (mach_code, tok) = process_cond_field(mach_code, tok)
        two_pass_line.append((tokens, line_count))
        
        
        
    return mach_code

def rotateIm(im_value):
    bin_list = bin(int(im_value))[2:]
    n = k = 0
    result = 0
    for idx, bit in enumerate(bin_list):
        if bit == "1":
            k = idx
    length = k - n + 1
    zeros = len(bin_list) - k - 1
    if zeros % 2 == 0:
        shift = int(16 - zeros / 2) << 8
    else:
        shift = int(16 - (zeros - 1) / 2) << 8

    if length <= 8:
        if length == 8 and (len(bin_list) - k - 1) % 2 == 1:
            sys.exit(1)
        else:
            if zeros % 2 == 0:
                result = str(bin_list[:k+1])
            else:
                result = str(bin_list[:k+1]) + "0"
        result = int("0b" + result, 2)
        result |= shift

    else:
        front_zeros  = 32 - len(bin_list)
        full_list = str(bin_list)
        i_len = 0
        j_len = 0

        for i in range(0,front_zeros):
            full_list = "0" + full_list

        for i in range(16, 0, -1):
            if full_list[i-1] == "1":
                i_len = i
                break
        for j in range(17, 33):
            if full_list[j-1] == "1":
                j_len = 32 - j + 1
                break

        if i_len + j_len > 8:
            sys.exit(1)
        elif (i_len + j_len == 8) and (j_len % 2 == 1):
            sys.exit(1)

        else:
            fore = full_list[:i_len]
            back = full_list[32 - j_len:]
            result = back + fore

            shift = int((len(fore) + 1) / 2) << 8
        
            if len(fore) % 2 == 1:
                result = result + "0"

            result = int("0b" + result, 2)
            result |= shift
    return result

results = {}
    
lines = sys.stdin.readlines()
splitter = re.compile(r'([ \t\n,])')

two_pass_line = []
symbol_table = {}
data_symbol_table = {}

count = 0
isData = False
literal_pool = {}

for line in lines:
    if isData == False:
        tokens = splitter.split(line)
        tokens = [tok for tok in tokens
                if re.match('\s*$', tok) == None]
        mach_code = 0
        while len(tokens) > 0 and isData == False:
            if tokens[0].endswith(':'): 
                label_name = tokens[0]
                tokens = tokens[1:]
                if len(tokens) == 0:
                    symbol_table[label_name.rstrip(":")] = hex(count)
                    break
                else:
                    if tokens[0] == ".word":
                        try:
                            if tokens[1].startswith("0x") or tokens[1].startswith("-0x"):
                                num = int(str(tokens[1]).lstrip("="), 16)
                            else:
                                num = int(str(tokens[1]).lstrip("="))

                            symbol_table[label_name.rstrip(":")] = hex(count)
                            mach_code = 0
                            string = "0x" + "0" * (8 - len(hex(num).lstrip("0x"))) + hex(num).lstrip("0x")
                            results[count] = string
                            count = count + 4
                            break
                        except:
                            sys.exit(1) 

                    elif tokens[0] == ".asciz":
                        symbol_table[label_name.rstrip(":")] = hex(count)
                        idx = line.find("\"")
                        string = line[idx + 1:len(line) - 2]
                        length = len(string) + 1
                        align_list = []
                        length = length - string.count("\\")
                        if length % 2 != 0:
                            sys.exit(1)
                        escape_flag = 0
                        for i in string:
                            if escape_flag == 1:
                                escape_flag = 0
                                align_list.append("\\" + i)
                            else:
                                if i == "\\":
                                    escape_flag = 1
                                    continue
                                else:
                                    align_list.append(i)
                        align_list.append("zero")
                        length = len(align_list)
                        for i in range(int(length / 4)):
                            text = ""
                            for j in range(4):
                                ch = str(align_list[i * 4 + j])
                                if ch.startswith("\\"):
                                    text = "0a" + text
                                elif ch == "zero":
                                    text = "00" + text
                                else:
                                    text = str(hex(ord(ch)).lstrip("0x")) + text
                                
                            text = "0x" + text
                            results[count] = text
                            count = count + 4
                        if length % 4 != 0:
                            text = ""
                            for j in range(2):
                                ch = str(align_list[len(align_list)-2 + j])
                                if ch.startswith("\\"):
                                    text = "0a" + text
                                elif ch == "zero":
                                    text = "00" + text
                                else:
                                    text = str(hex(ord(ch)).lstrip("0x")) + text
                            text = "0x" + text
                            results[count] = text
                            count = count + 2
                        break
                        
                    else:
                        symbol_table[label_name.rstrip(":")] = hex(count)
                        break
                        
                            
            elif tokens[0].startswith('.'): 
                if tokens[0] == ".data":
                    isData = True
                    break
                tokens = tokens[1:]
                continue

            else: 
                mach_code = process_instruction(tokens, count)
                results[count] = hex(mach_code)
                count = count + 4
                break
        if isData == True:
            continue
        
    else:
        tokens = splitter.split(line)
        tokens = [tok for tok in tokens
            if re.match('\s*$', tok) == None] 
        
        try :
            if not tokens[0].endswith(":"):
                if tokens[0] == ".end":
                    continue
                print("ERROR: Invalid syntax: 2")
                sys.exit(1) 

            if tokens[1] == ".word":
                if tokens[2].startswith("0x"):
                    if int(tokens[2],16) >= math.pow(2,32):
                        sys.exit(1) 
                    label = tokens[0].rstrip(":")
                    data_symbol_table[label] = 4
                    literal_pool[label] = 0
                else:
                    if int(tokens[2]) >= math.pow(2,32):
                        sys.exit(1) 
                    data_symbol_table[tokens[0].rstrip(":")] = 4
            
            elif tokens[1] == ".asciz":
                idx = line.find("\"")
                string = line[idx + 1:len(line) - 2]
                label = tokens[0].rstrip(":")
                length = len(string) - string.count("\\")
                data_symbol_table[label] = length + 1
                literal_pool[label] = 0
                
        except Exception as e:
            sys.exit(1) 
            
before = 0
flag = 1
for idx, (label, cost)  in enumerate(data_symbol_table.items()):
    try:
        int(label)
        before = 0
        flag = 1
        continue
    except:
        if flag == 1:
            data_symbol_table[label] = 0
            before = cost
            flag = 0
            continue

        else:
            data_symbol_table[label] = before
        before = before + cost

last = results.copy().popitem()[0]
if last % 4 != 0:
    results[last + 4] = "0x0000"
first = True
for line in two_pass_line:
    tokens = line[0]
    line_num = line[1] + 8
    if tokens[0].startswith("b"):
        target = int(symbol_table[tokens[1]], 16)
        offset = int((target - line_num) / 4)

        if offset < 0:
            offset = int(math.pow(2, 24) + offset )

        results[line[1]] = hex(int(results[line[1]], 16) | offset)
        
    elif tokens[0] == "ldr":
        label = str(tokens[3]).lstrip("=")
        result = 0
        isSymbol = False

        try:
            if label.startswith("0x") or label.startswith("-0x"):
                key = int(label, 16)
            else:
                key = int(label)
            literal_pool[key] = data_symbol_table[key]

            if label.startswith("0x"):  
                string = hex(key).lstrip("0x")
                zeros = "0" * (8 - len(string))
                
            elif label.startswith("-0x"):
                string = hex(int(math.pow(2,32)) + key).lstrip("0x")
                zeros = "0" * (8 - len(string))

            elif key >= 0:
                string = hex(key).lstrip("0x")
                zeros = "0" * (8 - len(string))

            else :
                string = hex(int(math.pow(2,32)) + key).lstrip("0x")
                zeros = "0" * (8 - len(string))
                

            idx = results.copy().popitem()[0]
            if idx % 4 == 2 and first == True:
                first = False
                results[idx + 2] = "0x" + zeros + string
            else:
                results[idx + 4] = "0x" + zeros + string

        except:
            idx = results.copy().popitem()[0]
            if label in symbol_table:
                literal_pool[label] = symbol_table[label]
                isSymbol = True
                string = symbol_table[label].lstrip("0x")
                zeros = "0" * (8 - len(string))
                if idx % 4 == 2 and first == True:
                    first = False
                    results[idx + 2] = "0x" + zeros + string
                else:
                    results[idx + 4] = "0x" + zeros + string
            else:
                literal_pool[label] = data_symbol_table[label]
                string = hex(data_symbol_table[label]).lstrip("0x")
                zeros = "0" * (8 - len(string))
                if idx % 4 == 2 and first == True:
                    first = False
                    results[idx + 2] = "0x" + zeros + string
                else:
                    results[idx + 4] = "0x" + zeros + string
            
        target = results.copy().popitem()[0]

        offset = target - line_num
        if offset <= 0:
            offset = -offset
        else:
            result |= 0b1 << 23 

        result |= registers[tokens[1]] << 12 
        result |= 0b1111 << 16 
        result |= offset 

        results[line[1]] = hex(int(results[line[1]], 16) | result)


    elif tokens[0] == "adr":
        result = 0
        label = str(tokens[3])
        offset = 0
        try:
            target = int(symbol_table[label], 16)
            offset = (target - line_num)
            if offset < 0: 
                result |= 0b001001001111 << 16
                offset = -offset
                
            else: 
                result |= 0b001010001111 << 16

            result |= registers[tokens[1]] << 12 

        except:
            sys.exit(1) 

        if offset >= 256:
            try:
                offset = rotateIm(offset)
            except:
                pass
        
        result |= offset

        results[line[1]] = hex(int(results[line[1]], 16) | result)
    else:
        pass
    

print("===machinenary code===")
for idx, (key, value) in enumerate(results.items()):
    print(hex(key + 32896)," : ", value)

print("===symbol table===")
for idx, line in enumerate(symbol_table):
    print(line, " : ",symbol_table[line])

print("===data symbol table===")
for idx, line in enumerate(data_symbol_table):
    print(line, " : ",data_symbol_table[line])
print("===literal pool ===")
for idx, line in enumerate(literal_pool):
    print(line, " : ",literal_pool[line])
