#include <assert.h>
#include <iostream>
#include <regex>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <vector>
#include <bitset>
#include <iostream>
#include <filesystem>
#include <array>

#define ARGS_COUNT_CHECK(N,DESC, LINE_SRC) if (args.size() != N) { \
                error = true; \
                std::cout << "\033[91mERROR: " << LINE_SRC << " Invalid number of arguments for " << DESC << "\033[0m" << std::endl; \
                return i; \
                }

class Memory;
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Host byte order must be little endian");

// Big Endian MIPS Simulator

std::vector<std::string> split(std::string str,std::string delim) {
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());
    return tokens;
}

std::string parse_string(std::string str) {
    // \ is escape character followed by octal number (3 digits) or any character
    std::string out;
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '\\') {
            std::string escape = str.substr(i, 4);
            // Check if excape is octal
            if(escape.size() == 4 && escape.find_first_not_of("01234567", 1) == std::string::npos) {
                out += (char)std::stoi(escape.substr(1), nullptr, 8);
                i += 3;
            } else {
                out += str[i + 1];
                i++;
            }
        } else {
            out += str[i];
        }
    }
    return out;
}

struct SourceGraphNode {
    std::string file;
    int start;
    int end;
    bool present = false;
    std::vector<std::shared_ptr<SourceGraphNode>> children;
    std::weak_ptr<SourceGraphNode> parent;
};

std::string getInclusionPath(SourceGraphNode& src_graph) {
    std::string path = src_graph.file;
    if (src_graph.parent.expired()) {
        return path;
    }
    return getInclusionPath(*src_graph.parent.lock()) + " -> " + path;
}

std::string getDescriptionForLine(SourceGraphNode& src_graph, unsigned line_num, std::string line) {
    // determine which file it is in
    std::string path = src_graph.file;
    unsigned lower = src_graph.start;
    int child_lines = 0;
    for (auto child : src_graph.children) {
        if (line_num >= child->start && line_num < child->end) {
            return getDescriptionForLine(*child, line_num, line);
        }
        if(line_num > child->start) {
            child_lines += child->end - child->start - 1; // 1 to include for %include line
        }
    }
    return path + ":" + std::to_string(line_num - lower - child_lines + 1) + " : " + line;
}



std::map<std::string, unsigned> reg_name = {
    {"$zero", 0},
    {"$at", 1},
    {"$v0", 2},
    {"$v1", 3},
    {"$a0", 4},
    {"$a1", 5},
    {"$a2", 6},
    {"$a3", 7},
    {"$t0", 8},
    {"$t1", 9},
    {"$t2", 10},
    {"$t3", 11},
    {"$t4", 12},
    {"$t5", 13},
    {"$t6", 14},
    {"$t7", 15},
    {"$s0", 16},
    {"$s1", 17},
    {"$s2", 18},
    {"$s3", 19},
    {"$s4", 20},
    {"$s5", 21},
    {"$s6", 22},
    {"$s7", 23},
    {"$t8", 24},
    {"$t9", 25},
    {"$k0", 26},
    {"$k1", 27},
    {"$gp", 28},
    {"$sp", 29},
    {"$fp", 30},
    {"$ra", 31},
    {"$0", 0},
    {"$1", 1},
    {"$2", 2},
    {"$3", 3},
    {"$4", 4},
    {"$5", 5},
    {"$6", 6},
    {"$7", 7},
    {"$8", 8},
    {"$9", 9},
    {"$10", 10},
    {"$11", 11},
    {"$12", 12},
    {"$13", 13},
    {"$14", 14},
    {"$15", 15},
    {"$16", 16},
    {"$17", 17},
    {"$18", 18},
    {"$19", 19},
    {"$20", 20},
    {"$21", 21},
    {"$22", 22},
    {"$23", 23},
    {"$24", 24},
    {"$25", 25},
    {"$26", 26},
    {"$27", 27},
    {"$28", 28},
    {"$29", 29},
    {"$30", 30},
    {"$31", 31}
};

unsigned symbol_to_imm(std::string symbol, std::map<std::string, unsigned>& labels,bool& error, std::string line_src) {
    // Check for %hi(symbol) or %lo(symbol)
    if (symbol.find("%hi(") == 0) {
        symbol = symbol.substr(4, symbol.size() - 5);
        if (labels.find(symbol) == labels.end()) {
            error = true;
            std::cout << "\033[91mERROR: " << line_src << " Unknown symbol in %hi(..)" << symbol << "\033[0m" << std::endl;
        }
        // if bit 15 is set, add 1 to the upper 16 bits to account for sign extension of %lo
        if (labels[symbol] & 0x8000) {
            return (labels[symbol] >> 16) + 1;
        }
        return labels[symbol] >> 16;
    }
    if (symbol.find("%lo(") == 0) {
        symbol = symbol.substr(4, symbol.size() - 5);
        if (labels.find(symbol) == labels.end()) {
            error = true;
            std::cout << "\033[91mERROR: " << line_src << " Unknown symbol in %lo(..)" << symbol << "\033[0m" << std::endl;
        }
        return labels[symbol] & 0xffff;
    }
    if(symbol.substr(0,2) == "0x") {
        return std::stoi(symbol, nullptr, 16);
    }
    if (symbol.find_first_not_of("0123456789-") == std::string::npos) {
        return std::stoi(symbol);
    }
    if (labels.find(symbol) == labels.end()) {
        error = true;
        std::cout << "\033[91mERROR: " << line_src << " Unknown symbol " << symbol << "\033[0m" << std::endl;
    }
    return labels[symbol];
}

unsigned reg_from_str(std::string reg, bool& error, std::string line_src) {
    if (reg_name.find(reg) == reg_name.end()) {
        std::cout << "\033[91mERROR: " << line_src << " Invalid register " << reg << "\033[0m" << std::endl;
        error = true;
        return 0;
    }
    return reg_name[reg];
}

std::string reg_to_str(unsigned reg) {
    for (auto it = reg_name.rbegin(); it != reg_name.rend(); it++) {
        if (it->second == reg) {
            return it->first;
        }
    }
    return "<unknown Reg: " + std::to_string(reg) + ">";
}

std::string imm_to_string(unsigned imm, std::map<std::string, unsigned>& labels) {
     if (labels.find(std::to_string(imm)) != labels.end()) {
         return std::to_string(labels[std::to_string(imm)]);
     }
    std::stringstream stream;
    stream << std::hex << imm;
    return "0x" + stream.str();
}

template <unsigned offset,unsigned length>
class AW32 {
    uint32_t* ptr;
public:
    AW32(uint32_t* ptr) : ptr(ptr) {}
    inline void operator=(uint32_t value) {
        uint32_t clr_mask = ((1 << length) - 1) << offset;
        uint32_t set_mask = (value & ((1 << length) - 1)) << offset;
        *ptr = (*ptr & ~clr_mask) | set_mask;
    }
    inline operator uint32_t() const {
        return (*ptr >> offset) & ((1 << length) - 1);
    }
};


/* It really sucks that the C++ standard doesn't guarantee that bitfields are in a specific order
    C++20 at least guarantees us that signed integers are twos complement, which is assumed throughout this code
*/
typedef uint32_t Instr;
/*
struct Instr {
    union {
        uint32_t val;
        struct __attribute__ ((packed)) {
            unsigned op: 6;
            unsigned rs: 5;
            unsigned rt: 5;
            unsigned rd: 5;
            unsigned shamt: 5;
            unsigned funct: 6;
        } R;

        struct __attribute__ ((packed)) {
            unsigned op: 6;
            unsigned rs: 5;
            unsigned rt: 5;
            unsigned imm: 16;
        } I;

        struct __attribute__ ((packed)) {
            unsigned op: 6;
            unsigned add: 26;
        } J;
    } __attribute__ ((packed));

    Instr(uint32_t i) {
        R.op = i >> 26;
        R.rs = (i >> 21) & 0x1f;
        R.rt = (i >> 16) & 0x1f;
        R.rd = (i >> 11) & 0x1f;
        R.shamt = (i >> 6) & 0x1f;
        R.funct = i & 0x3f;
    }
    uint32_t to_32() const {
        return (R.op << 26) | (R.rs << 21) | (R.rt << 16) | (R.rd << 11) | (R.shamt << 6) | R.funct;
    }
} __attribute__ ((packed));*/

#define INSTR_OP(X) (uint32_t)((uint32_t)(X) >> 26)
#define INSTR_RS(X) (uint32_t)(((uint32_t)(X) >> 21) & 0x1f)
#define INSTR_RT(X) (uint32_t)(((uint32_t)(X) >> 16) & 0x1f)
#define INSTR_RD(X) (uint32_t)(((uint32_t)(X) >> 11) & 0x1f)
#define INSTR_SHAMT(X) (uint32_t)(((uint32_t)(X) >> 6) & 0x1f)
#define INSTR_FUNCT(X) (uint32_t)((X) & 0x3f)
#define INSTR_IMM(X) (uint32_t)((X) & 0xffff)
#define INSTR_ADD(X) (uint32_t)((X) & 0x3ffffff)

#define INSTR_W_OP(X, V) (X) = ((X) & 0x3ffffff) | ((V) << 26)
#define INSTR_W_RS(X, V) (X) = ((X) & 0xff07ffff) | ((V) << 21)
#define INSTR_W_RT(X, V) (X) = ((X) & 0xffff07ff) | ((V) << 16)
#define INSTR_W_RD(X, V) (X) = ((X) & 0xfffff07f) | ((V) << 11)
#define INSTR_W_SHAMT(X, V) (X) = ((X) & 0xffffffc1) | ((V) << 6)
#define INSTR_W_FUNCT(X, V) (X) = ((X) & 0xffffffc0) | (V)
#define INSTR_W_IMM(X, V) (X) = ((X) & 0xffff0000) | ((V) & 0xffff)
#define INSTR_W_ADD(X, V) (X) = ((X) & 0xfc000000) | ((V) & 0x3ffffff)

static_assert(sizeof(Instr) == 4, "Invalid size for Instr");



class Memory {
public:
    unsigned start_addr = 0;
    unsigned size_bytes = 0;
    Memory(unsigned start, unsigned size) {
        start_addr = start;
        size_bytes = size;
    }

    unsigned size() {
        return size_bytes;
    }

    virtual void w_32(uint32_t addr, uint32_t value) {
        assert(addr + 3 < size());
        // Big Endian
        w_8(addr,(value >> 24) & 0xff);
        w_8(addr + 1,(value >> 16) & 0xff);
        w_8(addr + 2, (value >> 8) & 0xff);
        w_8(addr + 3, value & 0xff);
    }
    virtual void w_16(uint32_t addr, uint16_t value) {
        assert(addr + 1 < size());
        w_8(addr, (value >> 8) & 0xff);
        w_8(addr + 1, value & 0xff);
    }
    virtual uint32_t r_32(uint32_t addr) {
        assert(addr + 3 < size());
        return (r_8(addr) << 24) | (r_8(addr + 1) << 16) | (r_8(addr + 2) << 8) | r_8(addr + 3);
    }
    virtual uint16_t r_16(uint32_t addr) {
        assert(addr + 1 < size());
        return (r_8(addr) << 8) | r_8(addr + 1);
    }
    virtual uint32_t r_8(uint32_t addr) = 0;
    virtual void w_8(uint32_t addr, uint8_t value) = 0;
};

class RamMemory : public Memory {
    std::vector<uint8_t> mem;
public:
    RamMemory(unsigned start, unsigned size) : Memory(start, size) {
        mem.resize(size);
        std::fill(mem.begin(), mem.end(), 0);
    }
    virtual uint32_t r_8(uint32_t addr) {
        assert(addr < size());
        return mem[addr];
    }
    virtual void w_8(uint32_t addr, uint8_t value) {
        assert(addr < size());
        mem[addr] = value & 0xff;
    }
};


namespace Assembler {
    std::string disassemble(Instr i, std::map<std::string, unsigned>& labels) {
        std::string mnemonic;
        switch (INSTR_OP(i)) {
            case 0x0: // R-type
                switch (INSTR_FUNCT(i)) {
                    case 0x20: // add
                        return "add " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x21: // addu
                        return "addu " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x24: // and
                        return "and " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x08: // jr
                        return "jr " + reg_to_str(INSTR_RS(i));
                    case 0x27: // nor
                        return "nor " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x25: // or
                        return "or " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x2a: // slt
                        return "slt " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x00: // sll
                        return "sll " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RT(i)) + ", " + std::to_string(INSTR_SHAMT(i));
                    case 0x02: // srl
                        return "srl " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RT(i)) + ", " + std::to_string(INSTR_SHAMT(i));
                    case 0x22: // sub
                        return "sub " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    case 0x23: // subu
                        return "subu " + reg_to_str(INSTR_RD(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i));
                    default: return "<unknown funct> : " + std::to_string(INSTR_FUNCT(i));
                }
            break;
            case 0x08: // addi
                return "addi " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x09: // addiu
                return "addiu " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x0c: // andi
                return "andi " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x04: // beq
                return "beq " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x05: // bne
                return "bne " + reg_to_str(INSTR_RS(i)) + ", " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x02: // j
                return "j " + imm_to_string(INSTR_ADD(i) << 2, labels);
            case 0x03: // jal
                return "jal " + imm_to_string(INSTR_ADD(i) << 2, labels);
            case 0x20: // lb
                return "lb " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x24: // lbu
                return "lbu " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x25: // lhu
                return "lhu " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x30: // ll
                return "ll " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x0f: // lui
                return "lui " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x23: // lw
                return "lw " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x0d: // ori
                return "ori " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x0a: // slti
                return "slti " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x0b: // sltiu
                return "sltiu " + reg_to_str(INSTR_RT(i)) + ", " + reg_to_str(INSTR_RS(i)) + ", " + imm_to_string(INSTR_IMM(i), labels);
            case 0x28: // sb
                return "sb " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x38: // sc
                return "sc " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x29: // sh
                return "sh " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            case 0x2b: // sw
                return "sw " + reg_to_str(INSTR_RT(i)) + ", " + imm_to_string(INSTR_IMM(i), labels) + "(" + reg_to_str(INSTR_RS(i)) + ")";
            default: return "<unknown opcode> : " + std::to_string(INSTR_OP(i));
        }
        return mnemonic;
    }

    Instr assembleInstr(unsigned addr,std::string mnemonic, std::vector<std::string> args, bool& error, std::map<std::string, unsigned>& labels, std::string line_src) {
        Instr i = (Instr){0};
        if (mnemonic == "li") {
            ARGS_COUNT_CHECK(2, "li",line_src);
            INSTR_W_OP(i,0x08);
            INSTR_W_RS(i,0);
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
            //assert(INSTR_IMM(i) < 0b0111111111111111); // the immediate value can not be 1 at start (sign extension)
            std::cout << "\033[33mWARNING: " << line_src << " Using li as an alias for addi " << reg_to_str(INSTR_RT(i)) << ", $0, " << imm_to_string(INSTR_IMM(i), labels) << "\033[0m"<< std::endl;
        } else if (mnemonic == "nop") {
            ARGS_COUNT_CHECK(0, "nop",line_src);
            std::cout << "\033[33mWARNING: " << line_src << " Using nop as an alias for sll $zero, $zero, 0\033[0m" << std::endl;
        } else if (mnemonic == "move") {
            std::cout << "\033[33mWARNING: " << line_src << " Using move as an alias for add $1, $2, $0\033[0m" << std::endl;
            ARGS_COUNT_CHECK(2, "move",line_src);
            INSTR_W_FUNCT(i,0x20);
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
        }
        else if (mnemonic == "add") {
            ARGS_COUNT_CHECK(3, "add",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x20);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "addi") {
            ARGS_COUNT_CHECK(3, "addi",line_src);
            INSTR_W_OP(i,0x08);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "addiu") {
            ARGS_COUNT_CHECK(3, "addiu",line_src);
            INSTR_W_OP(i,0x09);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "addu") {
            ARGS_COUNT_CHECK(3, "addu",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x21);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        }
        else if (mnemonic == "andi") {
            ARGS_COUNT_CHECK(3, "andi",line_src);
            INSTR_W_OP(i,0x0c);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "beq") {
            ARGS_COUNT_CHECK(3, "beq",line_src);
            INSTR_W_OP(i,0x04);
            INSTR_W_RS(i,reg_from_str(args[0],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[1],error,line_src));
            unsigned target = symbol_to_imm(args[2],labels, error,line_src);
            INSTR_W_IMM(i,(target - addr - 4) >> 2);
        } else if (mnemonic == "bne") {
            ARGS_COUNT_CHECK(3, "bne",line_src);
            INSTR_W_OP(i,0x05);
            INSTR_W_RS(i,reg_from_str(args[0],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[1],error,line_src));
            unsigned target = symbol_to_imm(args[2],labels, error,line_src);
            INSTR_W_IMM(i,(target - addr - 4) >> 2);
        } else if (mnemonic == "j" || mnemonic == "b") {
            ARGS_COUNT_CHECK(1, "j",line_src);
            if(mnemonic == "b") {
                std::cout << "\033[33mWARNING: Using b as an alias for j\033[0m" << std::endl;
            }
            INSTR_W_OP(i,0x02);
            unsigned add = symbol_to_imm(args[0],labels, error,line_src);
            if(add % 4) {
                std::cout << "\033[91mERROR: " << line_src << " Jump address is not word aligned\033[0m" << std::endl;
                error = true;
            }
            INSTR_W_ADD(i,add >> 2);
        } else if (mnemonic == "jr") {
            ARGS_COUNT_CHECK(1, "jr",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x08);
            INSTR_W_RS(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "jal") {
            ARGS_COUNT_CHECK(1, "jal",line_src);
            INSTR_W_OP(i,0x03);
            auto addr = symbol_to_imm(args[0],labels, error,line_src);
            if(addr & 0x3) {
                std::cout << "\033[33mWARNING: Jump address is not word aligned\033[0m" << std::endl;
            }
            INSTR_W_ADD(i,symbol_to_imm(args[0],labels, error,line_src) >> 2);
        } else if (mnemonic == "lbu") {
            ARGS_COUNT_CHECK(3, "lbu",line_src);
            INSTR_W_OP(i,0x24);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "lb") {
            ARGS_COUNT_CHECK(3, "lb",line_src);
            INSTR_W_OP(i,0x20);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
            std::cout << "\033[33mWARNING: " << line_src << " Using lb even though it is not a core instruction\033[0m" << std::endl;
        } else if (mnemonic == "lhu") {
            ARGS_COUNT_CHECK(3, "lhu",line_src);
            INSTR_W_OP(i,0x25);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "ll") {
            ARGS_COUNT_CHECK(3, "ll",line_src);
            INSTR_W_OP(i,0x30);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "lui") {
            ARGS_COUNT_CHECK(2, "lui",line_src);
            INSTR_W_OP(i,0x0f);
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "lw") {
            ARGS_COUNT_CHECK(3, "lw",line_src);
            INSTR_W_OP(i,0x23);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "ori") {
            ARGS_COUNT_CHECK(3, "ori",line_src);
            INSTR_W_OP(i,0x0d);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "slti") {
            ARGS_COUNT_CHECK(3, "slti",line_src);
            INSTR_W_OP(i,0x0a);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "sltiu") {
            ARGS_COUNT_CHECK(3, "sltiu",line_src);
            INSTR_W_OP(i,0x0b);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "sb") {
            ARGS_COUNT_CHECK(3, "sb",line_src);
            INSTR_W_OP(i,0x28);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "sc") {
            ARGS_COUNT_CHECK(3, "sc",line_src);
            INSTR_W_OP(i,0x38);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "sh") {
            ARGS_COUNT_CHECK(3, "sh",line_src);
            INSTR_W_OP(i,0x29);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "sw") {
            ARGS_COUNT_CHECK(3, "sw",line_src);
            INSTR_W_OP(i,0x2b);
            INSTR_W_RS(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[0],error,line_src));
            INSTR_W_IMM(i,symbol_to_imm(args[1],labels, error,line_src));
        } else if (mnemonic == "sub") {
            ARGS_COUNT_CHECK(3, "sub",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x22);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "subu") {
            ARGS_COUNT_CHECK(3, "subu",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x23);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "nor") {
            ARGS_COUNT_CHECK(3, "nor",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x27);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "or") {
            ARGS_COUNT_CHECK(3, "or",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x25);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else if (mnemonic == "sll") {
            ARGS_COUNT_CHECK(3, "sll",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x00);
            INSTR_W_RT(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
            INSTR_W_SHAMT(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "srl") {
            ARGS_COUNT_CHECK(3, "srl",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x02);
            INSTR_W_RT(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
            INSTR_W_SHAMT(i,symbol_to_imm(args[2],labels, error,line_src));
        } else if (mnemonic == "slt") {
            ARGS_COUNT_CHECK(3, "slt",line_src);
            INSTR_W_OP(i,0x0);
            INSTR_W_FUNCT(i,0x2a);
            INSTR_W_RS(i,reg_from_str(args[1],error,line_src));
            INSTR_W_RT(i,reg_from_str(args[2],error,line_src));
            INSTR_W_RD(i,reg_from_str(args[0],error,line_src));
        } else {
            error = true;
            std::cout << "\033[91mERROR: " << line_src << " Invalid mnemonic " << mnemonic << "\033[0m" << std::endl;
        }
        //std::cout << "Assembled " << mnemonic << " to " << std::bitset<6>(i.R.op) << " " << std::bitset<5>(INSTR_RS(i)) << " " << std::bitset<5>(INSTR_RT(i)) << " " << std::bitset<5>(INSTR_RD(i)) << " " << std::bitset<5>(INSTR_SHAMT(i)) << " " << std::bitset<6>(INSTR_FUNCT(i))
        //<< " Bin:" << std::bitset<32>(i.to_32()) << std::endl;
        return i;
    }
    std::shared_ptr<Memory> assemble(std::vector<std::string> lines, uint32_t code_start ,std::map<std::string, uint32_t>& labels,bool& error, SourceGraphNode& source) {
        auto prog = std::make_shared<RamMemory>(code_start, 2048);
        std::regex r_label("^[\\s]*([\\$a-zA-Z0-9_]+):[\\s]*$");
        std::regex r_define("^[\\s]*%define[\\s]+([a-zA-Z0-9_]+)[\\s]+([a-zA-Z0-9_]+)[\\s]*$");
        std::regex r_dot("^[\\s]*\\.(word|ascii)[\\s]+(.*)$");
        std::regex r_mnm(R"([\s]*([a-zA-Z]+)[\s]*$)");
        std::regex r_mnm_reg_reg(R"([\s]*([a-zA-Z]+)[\s]*(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\$[a-zA-Z0-9]+)[\s]*$)");
        std::regex r_mnm_reg_num(R"([\s]*([a-zA-Z]+)[\s]+(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\%lo\([a-zA-Z0-9_]+\)|(\%hi\([a-zA-Z0-9_]+\)|[a-zA-Z0-9_])+))");
        std::regex r_mnm_reg_imm_reg(R"([\s]*([a-zA-Z]+)[\s]+(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\%(?:lo|hi)\([a-zA-Z_]+\)|[a-zA-Z0-9_]+)\(([$a-zA-Z0-9]+)\))");
        std::regex r_mnm_reg_reg_reg(R"([\s]*([a-zA-Z]+)[\s]+(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\$[a-zA-Z0-9]+))");
        std::regex r_mnm_reg_reg_num(R"([\s]*([a-zA-Z]+)[\s]+(\$[a-zA-Z0-9]+)[\s]*,[\s]*(\$[a-zA-Z0-9]+)[\s]*,[\s]*([\-a-zA-Z0-9_]+))");
        std::regex r_mnm_num(R"([\s]*([a-zA-Z]+)[\s]+([\$a-zA-Z0-9_]+))");
        int line_num = 0;
        // 1. Pass: Find labels
        int pos = code_start;
        for (auto line: lines) {
            std::string line_src = getDescriptionForLine(source, line_num, line);
            line = line.substr(0, line.find("#"));
            line = line.substr(0, line.find_last_not_of(" \t") + 1);
            if (line.empty()) {
                line_num++;
                continue;
            }
            std::smatch m;
            if (std::regex_match(line, m, r_label)) {
                labels[m[1]] = code_start + pos;
            } else if (std::regex_match(line, m, r_define)) {
                labels[m[1]] = symbol_to_imm(m[2], labels, error,line_src);
            } else if (std::regex_match(line, m, r_dot)) {
                if(m[1] == "word") {
                    pos += 4;
                } else if(m[1] == "ascii") {
                    std::string s = parse_string(m[2]);
                    if(s.length() < 2 || s[0] != '"' || s[s.length() - 1] != '"') {
                        std::cout << "\033[91mERROR(First Pass): " << line_src << " Invalid string format\033[0m" << std::endl;
                        error = true;
                    }
                    s = s.substr(1, s.length() - 2);
                    pos += parse_string(s).size();
                } else {
                    std::cout << "\033[91mERROR(First Pass): " << line_src << " Invalid directive\033[0m" << std::endl;
                    error = true;
                }
            } else if (std::regex_match(line, m, r_mnm_reg_num)) {
                pos += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_imm_reg)) {
                pos += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_reg_reg)) {
                pos += 4;
            } else if (std::regex_match(line, m, r_mnm_num)) {
                pos += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_reg_num)) {
                pos += 4;
            } else if (std::regex_match(line, m, r_mnm)) {
                pos += 4;
            }else if (std::regex_match(line, m, r_mnm_reg_reg)) {
                pos += 4;
            } else{
                std::cout << "\033[91mERROR(First Pass): " << line_src << " Invalid instruction format\033[0m" << std::endl;
                error = true;
            }
            line_num++;
        }
        // 2. Pass: Assemble instructions

        line_num = 0;
        unsigned address = code_start;
        for (auto line: lines) {
            std::string line_src = getDescriptionForLine(source, line_num, line);
            line = line.substr(0, line.find("#"));
            line = line.substr(0, line.find_last_not_of(" \t") + 1);
            if (line.empty()) {
                line_num++;
                continue;
            }
            std::smatch m;
            if (std::regex_match(line, m, r_label) || std::regex_match(line, m, r_define)) {
                // Skip
            } else if(std::regex_match(line, m, r_mnm)) {
                prog->w_32(address,assembleInstr(address,m[1], {}, error, labels,line_src));
                address += 4;
            } else if (std::regex_match(line, m, r_dot)) {
                assert(m.size() == 3);
                if(m[1] == "word") {
                    prog->w_32(address,symbol_to_imm(m[2], labels, error,line_src));
                    address += 4;
                } else if(m[1] == "ascii") {
                    std::string s = parse_string(m[2]);
                    if(s.length() < 2 || s[0] != '"' || s[s.length() - 1] != '"') {
                        std::cout << "\033[91mERROR(First Pass): " << line_src << " Invalid string format\033[0m" << std::endl;
                        error = true;
                    }
                    s = s.substr(1, s.length() - 2);
                    for (char c: s) {
                        prog->w_8(address, c);
                        address++;
                    }
                } else {
                    std::cout << "\033[91mERROR: " << line_src << " Invalid directive\033[0m" << std::endl;
                    error = true;
                }
            } else if (std::regex_match(line, m, r_mnm_reg_num)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2],m[3]}, error, labels,line_src));
                address += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_imm_reg)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2],m[3],m[4]}, error, labels,line_src));
                address += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_reg_reg)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2],m[3],m[4]}, error, labels,line_src));
                address += 4;
            } else if (std::regex_match(line, m, r_mnm_num)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2]}, error, labels,line_src));
                address += 4;
            } else if (std::regex_match(line, m, r_mnm_reg_reg_num)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2],m[3],m[4]}, error, labels,line_src));
                address += 4;
            }else if (std::regex_match(line, m, r_mnm_reg_reg)) {
                prog->w_32(address,assembleInstr(address,m[1], {m[2],m[3]}, error, labels,line_src));
                address += 4;
            } else {
                std::cout << "\033[91mERROR: " << line_src << " Invalid instruction format\033[0m" << std::endl;
                error = true;
            }
            line_num++;
        }
        if (error) {
            std::cout << "\033[91mError assembling code\033[0m" << std::endl;
        } else {
            std::cout << "\033[92mSUCCESS: Assembled code to " << address - code_start << " bytes \033[0m" << std::endl;
        }
        return prog;
    }
};

class MMU {
public:
    std::vector<std::shared_ptr<Memory>> memories;
    std::set<std::pair<uint32_t,uint32_t>> breakpoints;
    bool hit_bp = false;
    bool get_bp_and_clear() {
        if (hit_bp) {
            hit_bp = false;
            return true;
        }
        return false;
    }
    void add_breakpoint(uint32_t addr, uint32_t len) {
        breakpoints.insert({addr, addr + len});
    }

    bool register_potential_bp_hit(uint32_t base, uint32_t len) {
        hit_bp |= isBP(base, len);
        return hit_bp;
    }

    bool isBP(uint32_t base, uint32_t len) {
        for (auto& bp: breakpoints) {
            if (bp.first < base + len && bp.second > base) {
                return true;
            }
        }
        return false;
    }
    std::shared_ptr<Memory> at(uint32_t addr) {
        for (auto& mem: memories) {
            if (addr >= mem->start_addr && addr < mem->start_addr + mem->size()) {
                return mem;
            }
        }
        return nullptr;
    }
public:
    void map(std::shared_ptr<Memory> mem) {
        memories.push_back(mem);
    }
    void w_32(uint32_t addr, uint32_t value, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 4);
        auto mem = at(addr);
        if (mem) {
            mem->w_32(addr - mem->start_addr, value);
        }
    }
    void w_16(uint32_t addr, uint16_t value, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 2);
        auto mem = at(addr);
        if (mem) {
            mem->w_16(addr - mem->start_addr, value);
        }
    }
    void w_8(uint32_t addr, uint8_t value, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 1);
        auto mem = at(addr);
        if(mem) {
            mem->w_8(addr - mem->start_addr, value);
        }
    }
    uint32_t r_32(uint32_t addr, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 4);
        auto mem = at(addr);
        if (!mem) {
            return 0;
        }
        return mem->r_32(addr - mem->start_addr);
    }
    uint32_t r_16(uint32_t addr, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 2);
        auto mem = at(addr);
        if (!mem) {
            return 0;
        }
        return mem->r_16(addr - mem->start_addr);
    }
    uint32_t r_8(uint32_t addr, bool no_bp = false) {
        if(!no_bp) register_potential_bp_hit(addr, 1);
        auto mem = at(addr);
        if (!mem) {
            return 0;
        }
        return mem->r_8(addr - mem->start_addr);
    }
};

class CPU {
public:
    std::ostream& dbg = std::cout;
    std::array<uint32_t, 32> reg;
    MMU mmu;
    uint32_t pc = 0;
    uint32_t ir = 0;
    uint32_t hi;
    uint32_t lo;
    enum CPU_FEATURES : uint32_t {
        CPU_FEATURE_BRANCH_DELAY_SLOT = 0x1
    };
    uint32_t cpu_features_reg = 0;

    CPU() {
        std::fill(reg.begin(), reg.end(), 0);
    }
    static int32_t signExtend16(uint16_t imm) {
        if (imm & 0b1000000000000000) {
            return imm | 0xffff0000;
        }
        return imm;
    }
    static int32_t signExtend8(uint8_t imm) {
        if (imm & 0b10000000) {
            return imm | 0xffffff00;
        }
        return imm;
    }

    inline bool isBranchOrJump(uint32_t instr) {
        return INSTR_OP(instr) == 0x02 || INSTR_OP(instr) == 0x03 || INSTR_OP(instr) == 0x04 || INSTR_OP(instr) == 0x05
        || (INSTR_OP(instr) == 0 && (INSTR_FUNCT(instr) == 0x08));
    }
    void step() {
        reg[0] = 0;
        Instr instr(mmu.r_32(pc));
        uint32_t bdelay_slot_pc = pc + 4;
        switch (INSTR_OP(instr)) {
            case 0x0: // R-type
                switch (INSTR_FUNCT(instr)) {
                    case 0x20: // add
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] + reg[INSTR_RT(instr)];
                    break;
                    case 0x21: // addu
                        reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr));
                    break;
                    case 0x24: // and
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] & reg[INSTR_RT(instr)];
                    break;
                    case 0x08: // jr
                        pc = reg[INSTR_RS(instr)] - 4; // -4 because it will be incremented by 4 again
                    break;
                    case 0x27: // nor
                        reg[INSTR_RD(instr)] = ~(reg[INSTR_RS(instr)] | reg[INSTR_RT(instr)]);
                    break;
                    case 0x25: // or
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] | reg[INSTR_RT(instr)];
                    break;
                    case 0x2a: // slt
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] < reg[INSTR_RT(instr)];
                    break;
                    case 0x00: // sll
                        reg[INSTR_RD(instr)] = reg[INSTR_RT(instr)] << INSTR_SHAMT(instr);
                    break;
                    case 0x02: // srl
                        reg[INSTR_RD(instr)] = reg[INSTR_RT(instr)] >> INSTR_SHAMT(instr);
                    break;
                    case 0x22: // sub
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] - reg[INSTR_RT(instr)];
                    break;
                    case 0x23: // subu
                        reg[INSTR_RD(instr)] = reg[INSTR_RS(instr)] - reg[INSTR_RT(instr)];
                    break;
                    default:
                        std::cout << "Invalid funct" << std::endl;
                }
            break;
            case 0x08: // addi
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr));
            //pc = ir; // Generate overflow exception
            break;
            case 0x09: // addiu
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr));
            break;
            case 0x0c: // andi
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] & INSTR_IMM(instr);
            break;
            case 0x04: // beq
                if (reg[INSTR_RS(instr)] == reg[INSTR_RT(instr)]) {
                    pc += signExtend16(INSTR_IMM(instr)) << 2;
                }
            break;
            case 0x05: // bne
                if (reg[INSTR_RS(instr)] != reg[INSTR_RT(instr)]) {
                    pc += signExtend16(INSTR_IMM(instr)) << 2;
                }
            break;
            case 0x02: // j
                pc = ((pc + 4) & 0xf0000000) | (INSTR_ADD(instr) << 2);
            return;
            case 0x03: // jal
                reg[31] = pc + ((cpu_features_reg & CPU_FEATURE_BRANCH_DELAY_SLOT) ? 8 : 4);
                pc = (pc & 0xf0000000) | (INSTR_ADD(instr) << 2);
            return;
            case 0x24: // lbu
                reg[INSTR_RT(instr)] = mmu.r_8(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)));
                reg[INSTR_RT(instr)] &= 0xff;
            break;
            case 0x20: // lb
                reg[INSTR_RT(instr)] = signExtend8(mmu.r_8(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr))));
            break;
            case 0x25: // lhu
                reg[INSTR_RT(instr)] = mmu.r_16(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr) & 0xffff));
                reg[INSTR_RT(instr)] &= 0xffff;
            break;
            case 0x30: // ll
                reg[INSTR_RT(instr)] = mmu.r_32(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)));
            break;
            case 0x0f: // lui
                reg[INSTR_RT(instr)] = INSTR_IMM(instr) << 16;
            break;
            case 0x23: // lw
                reg[INSTR_RT(instr)] = mmu.r_32(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)));
            break;
            case 0x0d: // ori
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] | INSTR_IMM(instr);
            break;
            case 0x0a: // slti
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] < signExtend16(INSTR_IMM(instr));
            break;
            case 0x0b: // sltiu
                reg[INSTR_RT(instr)] = reg[INSTR_RS(instr)] < signExtend16(INSTR_IMM(instr));
            break;
            case 0x28: // sb
                mmu.w_8(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)),reg[INSTR_RT(instr)] & 0xff);
            break;
            case 0x38: // sc
                if (mmu.r_32(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr))) == reg[INSTR_RT(instr)]) {
                    reg[INSTR_RT(instr)] = 1;
                } else {
                    reg[INSTR_RT(instr)] = 0;
                }
            break;
            case 0x29: // sh
                mmu.w_16(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)), reg[INSTR_RT(instr)] & 0xffff);
            break;
            case 0x2b: // sw
                mmu.w_32(reg[INSTR_RS(instr)] + signExtend16(INSTR_IMM(instr)), reg[INSTR_RT(instr)]);
            break;
            default:
                throw std::runtime_error("Invalid opcode");
        }
        // run instr from branch delay slot
        if(isBranchOrJump(instr) && (cpu_features_reg & CPU_FEATURE_BRANCH_DELAY_SLOT)) {
            uint32_t tmp = pc;
            pc = bdelay_slot_pc;
            step();
            pc = tmp;
        }
        pc += 4;
    }

    void printRegs() {
        using namespace std;
        std::string breaker = " "; breaker.resize(145,'-');
        dbg << breaker << endl;
        dbg << "|  PC:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << pc;
        dbg << "  |  GP:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[28];
        dbg << "  |  SP:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[29];
        dbg << "  |  FP:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[30];
        dbg << "  |  RA:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[31];
        dbg << "  |  AT:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[1];
        dbg << "  |  V0:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[2];
        dbg << "  |  V1:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[3] << "  |" << endl;
        dbg << "|  A0:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[4];
        dbg << "  |  A1:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[5];
        dbg << "  |  A2:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[6];
        dbg << "  |  A3:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[7];
        dbg << "  |  K0:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[26];
        dbg << "  |  K1:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[27];
        dbg << "  |  T8:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[24];
        dbg << "  |  T9:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[25] << "  |" << endl;
        dbg << "|  T0:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[8];
        dbg << "  |  T1:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[9];
        dbg << "  |  T2:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[10];
        dbg << "  |  T3:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[11];
        dbg << "  |  T4:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[12];
        dbg << "  |  T5:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[13];
        dbg << "  |  T6:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[14];
        dbg << "  |  T7:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[15] << "  |" << endl;
        dbg << "|  S0:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[16];
        dbg << "  |  S1:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[17];
        dbg << "  |  S2:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[18];
        dbg << "  |  S3:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[19];
        dbg << "  |  S4:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[20];
        dbg << "  |  S5:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[21];
        dbg << "  |  S6:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[22];
        dbg << "  |  S7:" << std::showbase << std::setiosflags(std::ios::internal) << setfill('0') << std::setw(10) << std::hex << reg[23] << "  |" << endl;
        dbg << breaker << endl;
    }
#
    bool instr_labeled(uint32_t addr, std::map<std::string, unsigned>& labels, std::string& label_out) {
        for (auto& label: labels) {
            if (label.second == addr) {
                label_out = label.first;
                return true;
            }
        }
        return false;
    }

    void printState(std::map<std::string, unsigned>& labels,std::function<void(std::ostream& s,int)> display) {
        int height = 12;
        dbg << "\033[0;0H";
        printRegs();
        int pos = std::max((int)(pc - height*4), 0);
        int add = -std::min((int)(pc - height*4), 0);
        dbg << "   Address   |     HEX    |                Disassembly                  |                               VM Display                              |" << std::endl;
        int line = 0;
        while (pos < pc + height*4 + add) {
            Instr instr = (Instr)mmu.r_32(pos,true);
            std::string disassembly = Assembler::disassemble(instr,labels);
            disassembly.resize(43, ' ');
            std::string possible_label = "";
            if (instr_labeled(pos, labels, possible_label)) {
                disassembly = "\033[1;32m" + possible_label + "\033[0m: " + disassembly;
                disassembly.resize(54, ' ');
            }
            dbg << (mmu.isBP(pos, 4) ? "\033[1;31m" : "\033[0m")
            << ((pos == pc) ? "\033[4m->" :"  ")
            << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << pos
            <<  " | " << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << mmu.r_32(pos,true)
            << " | " << disassembly << "\033[0m | ";
            display(dbg, line);
            dbg << " |" << std::endl;
            line ++;
            pos += 4;
        }
        std::string breaker = " "; breaker.resize(145,'-');
        dbg << breaker << std::endl;
        dbg << "command >" << std::flush;


    }
};


enum CHAR_DISPLAY_ATTRS : uint32_t {
    FG_BLACK = 30,
    FG_DARK_RED = 31,
    FG_DARK_GREEN = 32,
    FG_DARK_YELLOW = 33,
    FG_DARK_BLUE = 34,
    FG_DARK_MAGENTA = 35,
    FG_DARK_CYAN = 36,
    FG_LIGHT_GRAY = 37,
    FG_DARK_GRAY = 90,
    FG_RED = 91,
    FG_GREEN = 92,
    FG_YELLOW = 93,
    FG_BLUE = 94,
    FG_MAGENTA = 95,
    FG_CYAN = 96,
    FG_WHITE = 97,

    BG_BLACK = 40,
    BG_DARK_RED = 41,
    BG_DARK_GREEN = 42,
    BG_DARK_YELLOW = 43,
    BG_DARK_BLUE = 44,
    BG_DARK_MAGENTA = 45,
    BG_DARK_CYAN = 46,
    BG_LIGHT_GRAY = 47,
    BG_DARK_GRAY = 100,
    BG_RED = 101,
    BG_GREEN = 102,
    BG_YELLOW = 103,
    BG_BLUE = 104,
    BG_MAGENTA = 105,
    BG_CYAN = 106,
    BG_WHITE = 107,

    SET_NORMAL = 0,
    SET_BOLD = 1,
    SET_DIM = 2,
    SET_UNDERLINE = 4,
    SET_BLINK = 5,
    SET_REVERSE = 7,
};

class CharacterDisplay : public RamMemory {
    enum config_entry : uint32_t {
        RESX = 0,
        RESY = 4,
        HEADER_SIZE = 8
    };
    unsigned start_addr;
    /* This is a simple display with the following header
     * int resx
     * int resy
     * Then 4 bytes per pixel
     * - (flag3) set 0=normal, 1=bold 2=dim 4=underline 5=blink 7=reverse 8=hidden
     * - (flag2) bg color
     * - (flag1) fg color
     * - character
     */
public:
    CharacterDisplay(int start_addr, int resx, int resy) : RamMemory(start_addr, resx * resy * 4 + HEADER_SIZE) {
        this->start_addr = start_addr;
        w_32(RESX, resx);
        w_32(RESY, resy);
        for (int i = 0; i < resx * resy; i++) {
            w_32(HEADER_SIZE + i * 4, 0x20 | (FG_LIGHT_GRAY << 8) | (FG_BLACK << 16) | (0 << 24));
        }
        std::string text = "<MIPS-VM> booted";
        int x = (resx - text.size()) / 2;
        int y = resy / 2;
        for (int i = 0; i < text.size(); i++) {
            w_32(HEADER_SIZE + (y * resx + x + i) * 4, text[i] | (SET_UNDERLINE << 8) | (FG_LIGHT_GRAY << 16) | (SET_BOLD << 24));
        }
    }
    int resx() {
        return r_32(RESX);
    }
    int resy() {
        return r_32(RESY);
    }
    std::string render_line(int y) {
        std::string result;
        assert(y < resy());
        for (int x = 0; x < resx(); x++) {
            uint32_t pixel = r_32(HEADER_SIZE + (y * resx() + x) * 4);
            uint8_t c = pixel & 0xff;
            uint8_t fg = (pixel >> 8) & 0xff;
            uint8_t bg = (pixel >> 16) & 0xff;
            uint8_t attr = (pixel >> 24) & 0xff;
            result += "\033[" + std::to_string(fg) + ";" + std::to_string(bg) + ";" + std::to_string(attr) + "m" + (char)c;
        }
        return result;
    }
};


// add RD, RS, RT   //  add $t7, $t0, $t1
// addi RT, RS, IMM

void collectSource(std::shared_ptr<SourceGraphNode> src_graph, std::vector<std::string>& code, bool& error) {
    // open file
    std::ifstream file(src_graph->file);
    if(!file.is_open()) {
        error = true;
        std::string included_from = getInclusionPath(*src_graph);
        std::cout << "\033[91mERROR: Could not open file: " << std::filesystem::absolute(src_graph->file) << (!included_from.empty()? " included through " + included_from  : "") << "\033[0m"<< std::endl;
    }
    // parse lines
    std::string str;
    src_graph->start = code.size();
    src_graph->end = 0;
    while (std::getline(file, str)) {
        // check if line is %include "..."
        std::smatch m;
        auto r_include = std::regex("(%include\\s+\"([^\"]+)\")");
        if (std::regex_match(str, m, r_include)) {
            auto path_of_file_including_this = std::filesystem::path(src_graph->file).parent_path();
            std::string included_file = m[2];
            std::filesystem::path included_path = path_of_file_including_this / included_file;
            // add child
            auto child = std::make_shared<SourceGraphNode>();
            child->file = included_path.string();
            child->parent = src_graph;
            src_graph->children.push_back(child);
            // collect source
            collectSource(child, code, error);
        } else {
            code.push_back(str);
        }
    }
    src_graph->end = code.size();
}

std::shared_ptr<Memory> assembleProgramm(std::string file_path, unsigned code_start, std::map<std::string, uint32_t>& labels) {
    // load all files including includes (%include "file.asm" where file.asm is relative to the current file)
    bool error = false;
    std::vector<std::string> lines;
    auto src_graph = std::make_shared<SourceGraphNode>();
    src_graph->file = file_path;
    collectSource(src_graph, lines, error);
    return Assembler::assemble(lines, code_start, labels,error,*src_graph);
}

void dumpMemory(CPU& cpu, unsigned start, int count) {
    for (int i = 0; i < count ; i+=4) {
        std::cout << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << start + i << " : " << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << cpu.mmu.r_32(start + i) << " " << std::endl;
    }
}



void runEmulator(std::map<std::string, uint32_t> labels, CPU& cpu, std::shared_ptr<CharacterDisplay> disp) {
    auto wait_line = [] () {
        std::cout << "Press enter to continue..." << std::endl;
        std::string in;
        std::getline(std::cin, in);
        std::cout << "\033[2J" << std::flush;
    };
    wait_line();
    while(true) {
        try {
            std::string help_msg = "Commands: \n"
            "s [n] - step [n] instructions\n"
            "r [n] - run [n] instructions\n"
            "stack [n] - dump stack [n] bytes\n"
            "b [addr] [len] - set breakpoint at addr with len\n"
            "b clear - clear all breakpoints\n"
            "q - quit\n"
            "help - show this message\n";
            std::cout << "\033[0J\033[1;1H";
            cpu.printState(labels, [&disp](std::ostream& s, int line) {
                s << disp->render_line(line);
            });
            std::string in;
            std::getline(std::cin, in);
            std::cout << "\033[1K" << std::flush;
            std::vector<std::string> cmd;
            cmd = split(in, " ");
            if (cmd.size() == 0) {
                cpu.step();
            } else if (cmd[0] == "q") {
                break;
            } else if (cmd[0] == "s") {
                if (cmd.size() == 2) {
                    for (int i = 0; i < std::stoi(cmd[1]); i++) {
                        cpu.step();
                    }
                } else {
                    cpu.step();
                }
            } else if (cmd[0] == "stack") {
                // dump everything above sp
                int n = 4 * 8;
                if (cmd.size() == 2) {
                    n = std::stoi(cmd[1]) * 4;
                }
                dumpMemory(cpu, cpu.reg[reg_name["$sp"]], n);
                wait_line();
            } else if (cmd[0] == "b") {
                if (cmd.size() == 1) {
                    std::cout << "Breakpoints:" << std::endl;
                    for (auto& bp: cpu.mmu.breakpoints) {
                        std::cout << "Breakpoint at " << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << bp.first << " len " << bp.second << std::endl;
                    }
                    wait_line();
                    continue;
                } else if (cmd.size() == 2 && cmd[1] == "clear") {
                    cpu.mmu.breakpoints.clear();
                    std::cout << "Cleared all breakpoints" << std::endl;
                    wait_line();
                    continue;
                } else {
                    bool err;
                    unsigned point = symbol_to_imm(cmd[1], labels, err,"");
                    unsigned len = 4;
                    if (cmd.size() == 3) {
                        len = std::stoi(cmd[2]);
                    }
                    cpu.mmu.add_breakpoint(point, len);
                    std::cout << "Added breakpoint <" << cmd[1] << "> at " << std::showbase << std::setiosflags(std::ios::internal) << std::setfill('0') << std::setw(10) << std::hex << point << " len " << len << std::endl;
                    wait_line();
                }
            } else if (cmd[0] == "r") {
                // run until breakpoint
                auto start_time = std::chrono::high_resolution_clock::now();
                unsigned steps = 0;
                unsigned max_steps = 10000;
                if (cmd.size() == 2) {
                    max_steps = std::stoi(cmd[1]);
                }
                bool bp = false;
                while(!(bp = cpu.mmu.get_bp_and_clear()) && steps < max_steps) {
                    cpu.step();
                    steps++;
                }
                auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - start_time).count();
                std::cout << (bp ? "Hit breakpoint " : "Executed ")
                << steps << " steps , took " << duration_ns << "ns (" << duration_ns / 1e6 << "ms) => " << (steps / 1e6) / (duration_ns / 1e9) << " MIPS" << std::endl;
                wait_line();
            }
            else {
                std::cout << "Invalid command" << std::endl;
                std::cout << help_msg;
                wait_line();
            }
        } catch (std::exception& e) {
            std::cout << "\033[eError: " << e.what() << std::endl;
            wait_line();
        }
    }
}

int main(int argc, char* argv[] ) {
    if(argc < 2) {
        std::cout << "Usage: " << argv[0] << " <file> optional: -BDELAYSLOT <0|1>" << std::endl;
        return 1;
    }
    std::map<std::string,std::vector<std::string>> features;
    std::set<std::string> supported_features = {"BDELAYSLOT"};
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg[0] == '-') {
            std::string feature = arg.substr(1);
            if (supported_features.find(feature) == supported_features.end()) {
                std::cout << "Unknown feature " << feature << std::endl;
                return 1;
            }
            features[feature] = {};
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                features[feature].push_back(argv[i + 1]);
                i++;
            }
        }
    }
    // Map Program into start of memory
    std::map<std::string, uint32_t> labels;
    auto prog = assembleProgramm(argv[1], 0, labels);
    CPU cpu;
    cpu.cpu_features_reg = (features["BDELAYSLOT"].size() > 0) ? CPU::CPU_FEATURE_BRANCH_DELAY_SLOT : 0;
    cpu.mmu.map(prog);
    // Map a stack
    cpu.mmu.map(std::make_shared<RamMemory>(1024, 1024));
    cpu.reg[reg_name["$sp"]] = 1024 + 1024;
    // Map a display
    auto disp = std::make_shared<CharacterDisplay>(4096, 69, 24);
    cpu.mmu.map(disp);
    runEmulator(labels, cpu, disp);
    return 0;
}
