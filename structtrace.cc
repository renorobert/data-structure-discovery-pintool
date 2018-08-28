#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <iomanip>
#include <string.h>

#define MMAP 	"mmap"
#define REALLOC "realloc"
#define CALLOC 	"calloc"
#define MALLOC 	"malloc"
#define SBRK 	"sbrk"
#define FREE 	"free"

std::ofstream TraceFile;
std::map <ADDRINT, std::string> instructions;
std::map <ADDRINT, ADDRINT> allocations;
ADDRINT allocsize = 0;
ADDRINT retaddress = 0;

/* Check if address belongs to main executable */
bool isMain(ADDRINT ret)
{
    PIN_LockClient();
    IMG im = IMG_FindByAddress(ret);
    PIN_UnlockClient();
    int inMain = IMG_Valid(im) ? IMG_IsMainExecutable(im) : 0;
    return inMain;
}

/* for malloc, mmap, sbrk, realloc allocations */
VOID AllocBefore(CHAR * name, ADDRINT size, ADDRINT ret)
{
    if(isMain(ret)) {
	retaddress = ret;
        allocsize = size;
        TraceFile << (ret-5) << "@" << name << "[" << allocsize << "]" << endl;
    }
}

/* for calloc allocation */
VOID CallocBefore(CHAR * name, ADDRINT nmemb, ADDRINT size, ADDRINT ret)
{
    if(isMain(ret)) {
	retaddress = ret;
        allocsize = nmemb * size;
        TraceFile << (ret-5) << "@" << name << "[" << allocsize << "]" << endl;
    }
}

VOID AllocAfter(ADDRINT retval)
{

    TraceFile << "ret" << "[" << retval << "]" << endl;

    if(retval > 0) {
        // if new address is returned
        if(allocations.count(retval) == 0) {   
            allocations.insert(std::make_pair(retval, allocsize));
        }
        // free() is not tracked, instead
        // if returned address already exists, update size of allocation
        else {
            std::map<ADDRINT, ADDRINT>::iterator it = allocations.find(retval);
	    it->second = allocsize;
	}
    }
}

/* filter stack based read/write operations */
bool INS_has_sp(INS ins) 
{					
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {

        REG op = INS_OperandMemoryBaseReg(ins, i);
	#ifdef __i386__ 
        if ((op == REG_ESP) || (op == REG_EBP))  return true;
	#else
	if ((op == REG_RSP) || (op == REG_RBP))  return true;
	#endif
    }

    return false;
}

VOID RtnInsertCall(IMG img, CHAR *funcname){
    RTN rtn = RTN_FindByName(img, funcname);

    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
	
	/* On function call */
	if(!strcmp(funcname, CALLOC)){
    	    RTN_InsertCall( rtn, 
		    IPOINT_BEFORE, 
		    (AFUNPTR)CallocBefore, 
		    IARG_ADDRINT, 
		    funcname, 
		    IARG_G_ARG0_CALLEE,
		    IARG_G_ARG1_CALLEE,
		    IARG_RETURN_IP,
		    IARG_END);
	}

	else if(!strcmp(funcname, MALLOC) ||
		!strcmp(funcname, SBRK)   ||
		!strcmp(funcname, FREE)) {
    	    RTN_InsertCall( rtn, 
		    IPOINT_BEFORE, 
		    (AFUNPTR)AllocBefore, 
		    IARG_ADDRINT, 
	    	    funcname, 
		    IARG_G_ARG0_CALLEE,
		    IARG_RETURN_IP,
		    IARG_END);
	}

	else if(!strcmp(funcname, REALLOC) ||
		!strcmp(funcname, MMAP)) {
    	    RTN_InsertCall( rtn, 
		    IPOINT_BEFORE, 
		    (AFUNPTR)AllocBefore, 
		    IARG_ADDRINT, 
		    funcname, 
		    IARG_G_ARG1_CALLEE,
		    IARG_RETURN_IP,
		    IARG_END);
	}
	
        RTN_Close(rtn);
    }
}

VOID Image(IMG img, VOID *v)
{
    // for tracking bss and data allocations in main executable
    if(IMG_IsMainExecutable(img)) {

	for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {

    	    const std::basic_string <char> sec_name = SEC_Name(sec);

	    // add bss and data sections to list of address to trace
	    if(!strcmp(sec_name.c_str(), ".bss") || !strcmp(sec_name.c_str(), ".data")) {

		ADDRINT addr = SEC_Address(sec);
		USIZE size = SEC_Size(sec);

                if(allocations.count(addr) == 0) {
                    allocations.insert(std::make_pair(addr, size));
		}

		TraceFile << sec_name << "[" << addr << "," << size << "]" << endl;
	    }
	}
    }

    RtnInsertCall(img, (CHAR*)SBRK);
    RtnInsertCall(img, (CHAR*)MALLOC);
    RtnInsertCall(img, (CHAR*)FREE);
    RtnInsertCall(img, (CHAR*)MMAP);
    RtnInsertCall(img, (CHAR*)REALLOC);
    RtnInsertCall(img, (CHAR*)CALLOC);
}


/* check if an address is part of allocated chunk  */
bool IsAllocatedAddress(ADDRINT addr)
{
    map<ADDRINT, ADDRINT>::iterator it;

    for (it = allocations.begin(); it != allocations.end(); it++) {
        if ((addr >= it->first) && (addr < it->first+it->second)) return true;
    }

    return false;
}


/* track only if target address is part of allocation */
VOID write_instruction(ADDRINT address, ADDRINT write_address, ADDRINT regval, CHAR *type)
{
    if(IsAllocatedAddress(write_address)) {

        std::string disass;

        if(instructions.count(address) > 0) {
            disass = instructions.at(address);
	}

        TraceFile << left << std::setw(10) << address << "@" << std::setw(40)  << disass;
        TraceFile << "   : " << type << " MEM[" << write_address << "] VAL[" << regval << "]" << endl;
    }
}

VOID read_instruction(ADDRINT address, ADDRINT read_address, ADDRINT size)
{
    if (IsAllocatedAddress(read_address)){

	std::string disass;

        if(instructions.count(address) > 0) {
            disass = instructions.at(address);
	}

	ADDRINT value = 0;
	if ((size == 8) || (size == 4)) value = *(ADDRINT *)read_address;
	else if (size == 1) value = *(char *) read_address;
        
        TraceFile << left << std::setw(10) << address << "@" << std::setw(40)  << disass;
        TraceFile << "   : MREAD VAL[" << value << "] MEM[" << read_address << "]" << endl;
    }
}

VOID TraceInstruction(INS ins, VOID *v)
{
    ADDRINT insaddr = INS_Address(ins);
    
    /* used instead of IPOINT_AFTER to fetch return value */
    if (insaddr == retaddress){
    	INS_InsertCall( ins,
                IPOINT_BEFORE,
                (AFUNPTR)AllocAfter,
		#ifdef __i386__ 
                IARG_REG_VALUE, LEVEL_BASE::REG_EAX,
                #else
		IARG_REG_VALUE, LEVEL_BASE::REG_RAX,
		#endif
                IARG_END);

    }
    if(isMain(insaddr) && (INS_Opcode(ins) == XED_ICLASS_MOV) 
	&& (INS_has_sp(ins) == false)) {

        std::string disass(INS_Disassemble(ins));

        if(instructions.count(INS_Address(ins)) == 0){
            instructions.insert(
	        std::make_pair(
                INS_Address(ins),
                disass));
        }
	
	if(INS_IsMemoryWrite(ins)) {

	    if(INS_OperandIsReg(ins, 1)) {

                REG src = INS_OperandReg(ins, 1);

                if(REG_valid(src)) {	
                    INS_InsertCall(
                        ins,
                        IPOINT_BEFORE,
                        (AFUNPTR)write_instruction,
                        IARG_ADDRINT, INS_Address(ins),
                        IARG_MEMORYWRITE_EA,   	// target address of memory write
		        IARG_REG_VALUE, src, 	// register value to be written
		        IARG_PTR , "WRREG",
                        IARG_END);
	        }
            }

	    else if(INS_OperandIsImmediate(ins, 1)) {

	        ADDRINT src = (ADDRINT)INS_OperandImmediate(ins, 1);

                INS_InsertCall(
                    ins,
                    IPOINT_BEFORE,
                    (AFUNPTR)write_instruction,
                    IARG_ADDRINT, INS_Address(ins),
                    IARG_MEMORYWRITE_EA,   	// target address of memory write
	            IARG_ADDRINT, src, 	// immediate value to be written
		    IARG_PTR, "WRIMM",
                    IARG_END);
	    }
        }
	else if(INS_IsMemoryRead(ins)) {
            INS_InsertCall(
                ins,
                IPOINT_BEFORE,
                (AFUNPTR)read_instruction,
                IARG_ADDRINT, INS_Address(ins),
                IARG_MEMORYREAD_EA,   // effective address of memory read
                IARG_MEMORYREAD_SIZE, // size in bytes
                IARG_END);
        }
    }
}


VOID Fini(INT32 code, VOID *v)
{
    TraceFile.close();
}

int main(int argc, char **argv)
{
    PIN_InitSymbols();
    if(PIN_Init(argc,argv)) return -1;

    // tracefile for PIN    
    TraceFile.open("StructTrace");

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(TraceInstruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
