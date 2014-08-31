/* Copyright (c) 2007, Determina Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Determina Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


//
// IDA Pro plugin for loading PDB files
// by Alexander Sotirov <asotirov@determina.com>
//
// Thanks to Matt Conover for the 64-bit support and to Ilfak Guilfanov
// for the copy-constructor bugfix.


#define _USE_32BIT_TIME_T   // IDA expects time_t to be a 32-bit value

#include <windows.h>
#include <dbghelp.h>

// IDA SDK includes

#pragma warning(push, 2)

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <bytes.hpp>
#include <typeinf.hpp>
#include <pe/pe.h>

#pragma warning(pop)

#ifndef VERSION
#define VERSION "(development version)"
#endif

#define PLUGIN_NAME "Determina PDB loader " VERSION

// ---------------------------------------------------------------------------
//
// Exception class
//

class Error {

protected:
    char str[MAXSTR];

public:
    Error() { str[0] = '\0'; }

    Error(const char* format, ...);

    // Show the error message in the IDA messages window
    void msg();
};


//
// Initialize an exception with a printf-style message
//

Error::Error(const char* format, ...)
{
    va_list va;

    va_start(va, format);
    qvsnprintf(str, sizeof(str), format, va);
    va_end(va);
}


//
// Show the error message in IDA
//

void Error::msg()
{
    ::msg("%s\n", str);
}


// ---------------------------------------------------------------------------
//
// DbgHelp API exception class
//

class DbgHelpError : public Error {

public:
    DWORD err;      // error code returned by GetLastError

    DbgHelpError(const char* format, ...);
};


//
// Initialize a DbgHelp API exception with a printf-style message and the
// last system error code
//

DbgHelpError::DbgHelpError(const char* format, ...)
{
    // Get the last system error code and format it as a string

    err = GetLastError();

    char buf[MAXSTR];

    if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL, err, 0, buf, sizeof(buf), NULL) == 0)
    {
        // FormatMessage failed, format the error code as a number
        qsnprintf(buf, sizeof(buf), "System error code %d", err);
    }

    // Initialize the exception with the printf-style message

    va_list va;

    va_start(va, format);
    qvsnprintf(str, sizeof(str), format, va);
    va_end(va);

    // Append the last system error code to the error message

    qstrncat(str, buf, sizeof(str));
}


// ---------------------------------------------------------------------------
//
// DbgHelp API class
//

class DbgHelp {

private:

    static int refcount;            // reference counter

    static HANDLE process;          // process handle passed to all DbgHelp
                                    // functions, but not really used

    // Disable the copy constructor and assignment operator

    DbgHelp(const DbgHelp& r);
    DbgHelp& operator=(const DbgHelp& r);

public:

    // Constructor and destructor

     DbgHelp();
    ~DbgHelp();

    // Set the DbgHelp option mask
    DWORD SymSetOptions(DWORD SymOptions);

    // Set the symbol search path
    void SymSetSearchPath(PCTSTR SearchPath);

    // Load the symbol table for a module
    DWORD64 SymLoadModule64(HANDLE hFile, PCSTR ImageName,
                            PCSTR ModuleName, DWORD64 BaseOfDll,
                            DWORD SizeOfDll);

    // Retrieve the module information of the specified module
    void SymGetModuleInfo64(DWORD64 dwAddr,
                                     PIMAGEHLP_MODULE64 ModuleInfo);

    // Enumerate all symbols in a process
    void SymEnumSymbols(ULONG64 BaseOfDll, PCTSTR Mask,
                        PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
                        PVOID UserContext);

    // Unload the symbol table for a module
    void SymUnloadModule64(DWORD64 BaseOfDll);

    // Undecorate a decorated C++ symbol name
    void UnDecorateSymbolName(PCTSTR DecoratedName, PTSTR UnDecoratedName,
                              DWORD UndecoratedLength, DWORD Flags);

    // Retrieve the function table entry for the specified address
    PVOID SymFunctionTableAccess64(DWORD64 AddrBase);
};


//
// Static variables used by the DbgHelp API
//

int DbgHelp::refcount = 0;
HANDLE DbgHelp::process = NULL;


//
// Initilize the DbgHelp API
//

DbgHelp::DbgHelp()
{
    if (refcount == 0) {

        // Initialize the debug API

        if (SymInitialize(process, NULL, FALSE) != TRUE)
            throw DbgHelpError("ERROR: SymInitialize failed: ");
    }

    refcount++;
}


//
// Free the resources used by the DbgHelp API
//

DbgHelp::~DbgHelp()
{
    if (refcount > 0)
        refcount--;

    if (refcount == 0) {
        if (SymCleanup(process) != TRUE) {
            DbgHelpError error("ERROR: SymCleanup failed: ");
            error.msg();    // show the error message
        }
    }
}


//
// Set the DbgHelp option mask
//

DWORD DbgHelp::SymSetOptions(DWORD SymOptions)
{
    return ::SymSetOptions(SymOptions);
}


//
// Set the symbol search path
//

void DbgHelp::SymSetSearchPath(PCTSTR SearchPath)
{
    if (::SymSetSearchPath(process, SearchPath) != TRUE)
        throw DbgHelpError("ERROR: SymSetSearchPath failed: ");
}


//
// Load the symbol table for a module
//

DWORD64 DbgHelp::SymLoadModule64(HANDLE hFile, PCSTR ImageName,
                                 PCSTR ModuleName, DWORD64 BaseOfDll,
                                 DWORD SizeOfDll)
{
    DWORD64 base;

    base = ::SymLoadModule64(process, hFile, ImageName, ModuleName, BaseOfDll,
                             SizeOfDll);

    if (base == 0)
        throw DbgHelpError("ERROR: SymLoadModule64 failed: ");

    return base;
}


//
// Retrieve the module information of the specified module
//

void DbgHelp::SymGetModuleInfo64(DWORD64 dwAddr, PIMAGEHLP_MODULE64 ModuleInfo)
{
    if (::SymGetModuleInfo64(process, dwAddr, ModuleInfo) != TRUE)
        throw DbgHelpError("ERROR: SymGetModuleInfo64 failed: ");
}


//
// Enumerate all symbols in a process
//

void DbgHelp::SymEnumSymbols(ULONG64 BaseOfDll, PCTSTR Mask,
                    PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
                    PVOID UserContext)
{
    if (::SymEnumSymbols(process, BaseOfDll, Mask, EnumSymbolsCallback,
                         UserContext) != TRUE)
        throw DbgHelpError("ERROR: SymEnumSymbols failed: ");
}


//
// Unload the symbol table for a module
//

void DbgHelp::SymUnloadModule64(DWORD64 BaseOfDll)
{
    if (::SymUnloadModule64(process, BaseOfDll) != TRUE)
        throw DbgHelpError("ERROR: SymUnloadModule64 failed: ");
}


//
// Undecorate a decorated C++ symbol name
//

void DbgHelp::UnDecorateSymbolName(PCTSTR DecoratedName, PTSTR UnDecoratedName,
                                   DWORD UndecoratedLength, DWORD Flags)
{
    if (::UnDecorateSymbolName(DecoratedName, UnDecoratedName,
                               UndecoratedLength, Flags) == 0)
        throw DbgHelpError("ERROR: UnDecorateSymbolName failed to demangle symbol %s: ",
                           DecoratedName);
}

//
// Retrieve the function table entry for the specified address
//

PVOID DbgHelp::SymFunctionTableAccess64(DWORD64 AddrBase)
{
    PVOID fpo = ::SymFunctionTableAccess64(process, AddrBase);
    if (fpo == NULL)
        throw DbgHelpError("ERROR: SymFunctionTableAccess64 failed: ");

    return fpo;
}


// Symbol types

enum sym_type {
    SYM_UNKNOWN = 0,
    SYM_FLOAT,
    SYM_DOUBLE,
    SYM_STRING,
    SYM_FUNC,
    SYM_IMPORT,
    SYM_VTABLE,
    SYM_DATA,
    SYM_GUID
};


// ---------------------------------------------------------------------------
//
// Symbol information class
//

class Sym {

private:
    DbgHelp dbghelp;    // Use the DbgHelp API

    // Returns true if the symbol name looks like a GUID structure
    bool is_guid();

    // Determine the symbol type
    enum sym_type find_type();

    // Returns true if none of the bytes in the range has a name
    bool check_name_range(ea_t addr, int len);

    // Create a 4 or 8 byte pointer at the specified address
    void create_pointer(ea_t addr, size_t ptr_size);

    // Disable assignment operator
    Sym& operator=(const Sym &r);

public:
    ea_t          addr;             // address in the IDA database
    SYMBOL_INFO*  symbol_info;      // SYMBOL_INFO structure from DbgHelp
    char*         demangled_name;   // demangled name from DbgHelp
    FPO_DATA*     fpo;              // FPO data from DbgHelp
    enum sym_type type;             // symbol type

    // Constructor, copy constructor and destructor

     Sym(SYMBOL_INFO *symbol_info, ea_t addr);
     Sym(const Sym &r);
    ~Sym();

    // Apply the name of a symbol in the IDA database
    void apply_name();

    // Apply a symbol in the IDA database
    void apply();

    // Comparison function, used by qsort
    static int __cdecl compare(const void *a, const void *b);
};


//
// Initialize a Sym object from a SYMBOL_INFO structure. The addr parameter
// specifies address of the symbol in the IDA database
//

Sym::Sym(SYMBOL_INFO *symbol_info, ea_t addr)
{
    this->addr = addr;

    // Copy the dynamically sized SYMBOL_INFO structure

    unsigned int size = symbol_info->SizeOfStruct + symbol_info->MaxNameLen - 1;

    this->symbol_info = (SYMBOL_INFO*)qalloc(size);
    memcpy(this->symbol_info, symbol_info, size);

    // Demangle the name

    char demangled_name[MAXSTR];

    this->demangled_name = NULL;

    try {
        dbghelp.UnDecorateSymbolName(symbol_info->Name, demangled_name,
                                     sizeof(demangled_name), UNDNAME_COMPLETE);

        // Set the demangled name if it is different than the mangled name,
        // leave it as NULL otherwise

        if (strcmp(symbol_info->Name, demangled_name) != 0)
            this->demangled_name = qstrdup(demangled_name);
    }
    catch (DbgHelpError& error) {
        error.msg();        // show the error message
    }

    // Get the FPO data

    try {
        this->fpo = (FPO_DATA*)dbghelp.SymFunctionTableAccess64(symbol_info->Address);
    }
    catch (DbgHelpError& error) {

        // ERROR_INVALID_ADDRESS is expected

        if (error.err != ERROR_INVALID_ADDRESS) {
            error.msg();        // show the error message
        }

        this->fpo = NULL;
    }

    // Get the symbol type

    this->type = find_type();
}


//
// Copy constructor
//

Sym::Sym(const Sym &r)
{
    this->addr = r.addr;
    this->fpo = r.fpo;
    this->type = r.type;

    // Copy the dynamically sized SYMBOL_INFO structure

    unsigned int size = r.symbol_info->SizeOfStruct + r.symbol_info->MaxNameLen - 1;

    this->symbol_info = (SYMBOL_INFO*)qalloc(size);
    memcpy(this->symbol_info, r.symbol_info, size);

    // Copy the demangled name if it's not NULL

    if (r.demangled_name == NULL)
        this->demangled_name = NULL;
    else
        demangled_name = qstrdup(r.demangled_name);
}


//
// Destroy a Sym object
//

Sym::~Sym()
{
    if (this->demangled_name != NULL)
        qfree(this->demangled_name);

    qfree(this->symbol_info);
}


//
// Returns true if the symbol name looks like a GUID structure
//

// Disable the warning about assignment within conditional expression
#pragma warning(disable:4706)

#define CHECK_NAME(x) \
    (strncmp(name, x, sizeof(x)-1) == 0 && (len = sizeof(x)-1))

bool Sym::is_guid()
{
    // GUID variables don't have a demangled name

    if (this->demangled_name != NULL)
        return false;

    // Get the mangled name

    char* name = this->symbol_info->Name;

    // Skip leading underscores

    while (*name == '_') name++;

    // Check if the name starts with one of the following prefixes:

    int len = 0;

    if (CHECK_NAME("BFID_")  ||
        CHECK_NAME("BHID_")  ||
        CHECK_NAME("CATID_") ||
        CHECK_NAME("CLSID_") ||
        CHECK_NAME("CGID_")  ||
        CHECK_NAME("DIID_")  ||
        CHECK_NAME("FMTID_") ||
        CHECK_NAME("GUID_")  ||
        CHECK_NAME("IID_")   ||
        CHECK_NAME("LIBID_") ||
        CHECK_NAME("MSPID_") ||
        CHECK_NAME("POLID_") ||
        CHECK_NAME("SCID_")  ||
        CHECK_NAME("SID_")   ||
        CHECK_NAME("SRCID_") ||
        CHECK_NAME("TOID_")  ||
        CHECK_NAME("UICID_") ||
        CHECK_NAME("VID_"))
    {
        // Check if the rest of the name consists of [a-zA-Z0-9_]

        for (char* p = name + len; *p != '\0'; p++) {
            if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
                !(*p >= '0' && *p <= '9') && !(*p == '_'))
                return false;
        }

        // Looks like a GUID structure

        return true;
    }

    return false;
}

#undef CHECK_NAME

#pragma warning(default:4706)


//
// Determine the symbol type
//

enum sym_type Sym::find_type()
{
    char* name = this->symbol_info->Name;

    // Get the segment type for the symbol address
    uchar seg_type = segtype(addr);

    // Guess the type of the symbol based on it's mangled name
    mangled_name_type_t mangled_name_type = get_mangled_name_type(name);

    //
    // Functions
    //

    // Symbols with FPO information are definitely functions

    if (this->fpo != NULL)
        return SYM_FUNC;

    // Handle imports that look like functions, for example the import
    // __imp__DSA_DeleteItem@8 in browseui.dll on Windows XP SP2

    if (demangled_name == NULL &&
        strncmp(name, "__imp__", sizeof("__imp__")-1) == 0)
    {
        return SYM_IMPORT;
    }

    // Detect functions in the code or normal segment using the demangler

    if (seg_type == SEG_NORM || seg_type == SEG_CODE) {
        if (mangled_name_type == MANGLED_CODE) {
            return SYM_FUNC;
        }
    }

    //
    // Imports
    //

    if (seg_type == SEG_XTRN)
        return SYM_IMPORT;

    //
    // Real literals
    //

    if (strncmp(name, "__real@", sizeof("__real@")-1) == 0) {
        switch (strlen(name)) {
            case 15:    // __real@3fc00000
                return SYM_FLOAT;

            case 23:    // __real@0000000000000000
                return SYM_DOUBLE;

            case 29:    // __real@8@00000000000000000000
                if (strncmp(name, "__real@8@", sizeof("__real@8@")-1) == 0)
                    return SYM_DOUBLE;

                // else fall through

            default:
                msg("%a: WARNING: Real literal with an invalid size %s\n",
                    addr, name);
                break;
        }
    }

    //
    // String literals
    //

    if (this->demangled_name != NULL &&
        strcmp(this->demangled_name, "`string'") == 0)
    {
        return SYM_STRING;
    }

    //
    // Vtables
    //

    if (this->demangled_name != NULL &&
        strstr(this->demangled_name, "`vftable'") != NULL)
    {
        return SYM_VTABLE;
    }

    //
    // Data
    //

    if (mangled_name_type == MANGLED_DATA)
        return SYM_DATA;

    //
    // GUIDs
    //

    if (is_guid() == true)
        return SYM_GUID;

    return SYM_UNKNOWN;
}


//
// Apply the name of a symbol in the IDA database
//

void Sym::apply_name()
{
    char truncated[MAXNAMELEN];

    char* name = this->symbol_info->Name;

    // Tail bytes cannot have names, so we have to undefine it

    if (isTail(get_flags_novalue(addr)))
        do_unknown(addr, true);

    // Truncate the name if it's longer than MAXNAMELEN

    if (strlen(name) > MAXNAMELEN-1) {
        msg("%a: WARNING: Truncating name to %d characters: %s\n",
            addr, MAXNAMELEN, name);

        // Prepend the address to the name, because otherwise we might
        // get two identical names after the truncation

        qsnprintf(truncated, MAXNAMELEN, "trunc_%a__%s", addr, name);

        name = truncated;
    }

    // Set the name

    if (set_name(addr, name, SN_NOCHECK | SN_NOWARN) == 0)
        msg("%a: WARNING: Failed to set name %s\n", addr, name);

    return;
}


//
// Returns true if none of the bytes in the range has a name
//

bool Sym::check_name_range(ea_t addr, int len)
{
    for (ea_t ea = addr+1; ea < addr+len; ea++) {
        if (has_any_name(get_flags_novalue(ea)) == true)
            return false;
    }

    return true;
}


//
// Create a pointer at the specified address
//

void Sym::create_pointer(ea_t addr, size_t ptr_size)
{
    if (ptr_size == 8) {
        do_unknown_range(addr, 8, 0);
        doQwrd(addr, 8);
    }
    else {
        do_unknown_range(addr, 4, 0);
        doDwrd(addr, 4);
    }
}


//
// Apply a symbol in the IDA database
//

void Sym::apply()
{
    char* name = this->symbol_info->Name;

    showAddr(addr); // so the user doesn't get bored

    // Get the current segment

    segment_t *seg;

    if ((seg = getseg(addr)) == NULL) {
        msg("%a: ERROR: Unable to get segment for %s\n", addr, name);
        return;
    }

    // Get the width of pointers in the current segment

    int ptr_size = seg->use64() ? 8 : 4;

#ifndef __EA64__
    if (ptr_size == 8) {
        msg("%a: ERROR: 64-bit segment not supported by IDA\n", addr, name);
        return;
    }
#endif

    // Process symbols types

    switch (type) {
        case SYM_FLOAT:
            if (check_name_range(addr, 4) == false) {
                msg("%a: WARNING: Not enough space for a float %s\n",
                    addr, name);
                break;
            }
            do_unknown_range(addr, 4, 0);
            doFloat(addr, 4);
            break;

        case SYM_DOUBLE:
            if (check_name_range(addr, 8) == false) {
                msg("%a: WARNING: Not enough space for a double %s\n",
                    addr, name);
                break;
            }
            do_unknown_range(addr, 8, 0);
            doDouble(addr, 8);
            break;

        case SYM_STRING:
        {
            //
            // Get the length of an ASCII string at this location
            //

            asize_t ascii_len = 0;

            for (ea_t ea = addr; ea < seg->endEA; ea++) {

                uint8 ch;

                // make sure that we have enough space for a character
                if (check_name_range(addr, 1) == false)
                    break;

                // get the character
                if (get_many_bytes(ea, &ch, 1) == 0)
                    break;

                if (ch == '\0') {
                    ascii_len = ea - addr + 1;
                    break;
                }
            }

            //
            // Get the length of an UNICODE string at this location
            //

            asize_t unicode_len = 0;

            for (ea_t ea = addr; ea < seg->endEA; ea = ea + 2) {

                uint16 ch;

                // make sure that we have enough space for a character
                if (check_name_range(addr, 2) == false)
                    break;

                // get the character
                if (get_many_bytes(ea, &ch, 2) == 0)
                    break;

                // we count only Basic Latin and Latin-1 Supplement characters
                if (ch > 0xFF)
                    break;

                if (ch == L'\0') {
                    unicode_len = ea - addr + 2;
                    break;
                }
            }

            if (ascii_len == 0 && unicode_len == 0) {
                msg("%a: WARNING: Cannot determine string type\n", addr);
                break;
            }

            // Remove the `string' name, make_ascii_string will generate a
            // better one
            set_name(addr, "", SN_NOWARN);

            if (ascii_len >= unicode_len) {

                // Create an ASCII string

                do_unknown_range(addr, (size_t)ascii_len, 0);
                if (!make_ascii_string(addr, (size_t)ascii_len, ASCSTR_C)) {
                    msg("%a: WARNING: failed to create a %d byte ASCII string\n",
                        addr, ascii_len);
                }
            }
            else {

                // Create a UNICODE string

                do_unknown_range(addr, (size_t)unicode_len, 0);
                if (!make_ascii_string(addr, (size_t)unicode_len, ASCSTR_UNICODE)) {
                    msg("%a: WARNING: failed to create a %d byte UNICODE string\n",
                        addr, unicode_len);
                }
            }
            break;
        }

        case SYM_FUNC:
            add_func(addr, BADADDR);
            break;

        case SYM_IMPORT:
            if (check_name_range(addr, ptr_size) == false) {
                msg("%a: WARNING: Not enough space for an import %s\n",
                    addr, name);
                break;
            }
            create_pointer(addr, ptr_size);
            break;

        case SYM_VTABLE:

            // Create the first element of the vtable

            if (check_name_range(addr, ptr_size) == false) {
                msg("%a: WARNING: Not enough space for a vtable %s\n",
                    addr, name);
                break;
            }
            create_pointer(addr, ptr_size);

            // Loop until we reach the end of the vtable

            for (ea_t ea = addr+ptr_size; ea < seg->endEA; ea = ea + ptr_size) {

                ea_t func_addr;

                // make sure that we have enough space for a pointer
                if (check_name_range(addr, ptr_size) == false)
                    break;

                // get the function pointer
                if (ptr_size == 8) {
                    uint64 ptr;
                    if (get_many_bytes(ea, &ptr, 8) == 0)
                        break;

                    func_addr = (ea_t)ptr;
                }
                else {
                    uint32 ptr;
                    if (get_many_bytes(ea, &ptr, 4) == 0)
                        break;

                    func_addr = ptr;
                }

                // make sure that it points to a code or normal segment
                uchar seg_type = segtype(func_addr);
                if (seg_type != SEG_CODE && seg_type != SEG_NORM)
                    break;

                // create a function pointer in the vtable
                create_pointer(ea, ptr_size);
            }
            break;

        case SYM_DATA:
            // TODO: try to guess the type of the data and define it
            break;

        case SYM_GUID:
            if (check_name_range(addr, 16) == false) {
                msg("%a: WARNING: Not enough space for a GUID %s\n",
                    addr, name);
                break;
            }
            do_unknown_range(addr, 16, 0);

            if (apply_cdecl(addr, "GUID x;") == false) {
                msg("%a: WARNING: Cannot create GUID structure %s\n",
                    addr, name);
            }
            break;

        case SYM_UNKNOWN:
            break;

        default:
            throw Error("%a: ERROR: Unknown symbol type %d for %s",
                addr, type, name);
    }

    return;
}


//
// Comparison function used by qsort
//

int __cdecl Sym::compare(const void *a, const void *b)
{
    Sym* sym_a = (Sym*)a;
    Sym* sym_b = (Sym*)b;

    if (sym_a->symbol_info->Address < sym_b->symbol_info->Address)
        return -1;
    else if (sym_a->symbol_info->Address > sym_b->symbol_info->Address)
        return +1;
    else
        // If we have multiple names for an address, sort them alphabetically
        return strcmp(sym_a->symbol_info->Name, sym_b->symbol_info->Name);
}


// ---------------------------------------------------------------------------
//
// Symbol table class
//

class Symbols {

private:
    DbgHelp dbghelp;                // Use the DbgHelp API

    ea_t image_base;                // IDA image base
    DWORD64 symbols_base;           // DbgHelp image base

    qvector<Sym> array;             // array of symbols

    // Disable the copy constructor and assignment operator

    Symbols(const Symbols& r);
    Symbols& operator=(const Symbols& r);

public:
    IMAGEHLP_MODULE64 module_info;  // information about the loaded module

    // Get all symbols for a file loaded at a specific image base
    Symbols(char* file, ea_t image_base);

    // Unload the symbol table for the file
    ~Symbols();

    // Add a symbol to the array
    void add(SYMBOL_INFO *symbol_info);

    // Returns the number of symbols in the array
    unsigned int num();

    // Returns the symbol at a specified index (0..num()-1)
    Sym* get(unsigned int n);

    // Apply all symbols
    void apply();

    // Callback function for enumerating symbols from DbgHelp
    static BOOL CALLBACK enum_symbols_proc(PSYMBOL_INFO pSymInfo,
                                           ULONG SymbolSize,
                                           PVOID UserContext);
};


//
// Get all symbols for a file loaded at a specific image base
//

Symbols::Symbols(char* file, ea_t image_base)
{
    this->image_base = image_base;

    // Load the symbols for the file

    try {
        symbols_base = dbghelp.SymLoadModule64(NULL, file, NULL, 0, 0);
    }
    catch (DbgHelpError& error) {
        if (error.err == ERROR_INVALID_HANDLE)
            throw Error("ERROR: File %s not found", file);
        else
            throw;
    }

    try {

        // Find out what kind of symbols we loaded

        memset(&module_info, '\0', sizeof(module_info));
        module_info.SizeOfStruct = sizeof(module_info);

        dbghelp.SymGetModuleInfo64(symbols_base, &module_info);

        if (module_info.SymType == SymDeferred ||
            module_info.SymType == SymExport ||
            module_info.SymType == SymNone)
        {
            throw Error("ERROR: No symbols found");
        }

        if (module_info.LoadedPdbName != NULL &&
            strcmp(module_info.LoadedPdbName, "") != 0)
        {
            msg("PDB symbols: %s\n", module_info.LoadedPdbName);
        }

        if (module_info.LoadedImageName != NULL &&
            strcmp(file, module_info.LoadedImageName) != 0)
        {
            msg("DBG symbols: %s\n", module_info.LoadedImageName);
        }

        // Enumarate all symbols and create the array of Sym objects

        dbghelp.SymEnumSymbols(symbols_base, NULL, &enum_symbols_proc, this);

        // Sort the symbols by their addresses and names

        qsort(&array[0], array.size(), sizeof(Sym), &Sym::compare);

    } catch (Error&) {

        // Unload the file

        try {
            dbghelp.SymUnloadModule64(symbols_base);
        }
        catch (DbgHelpError&) {
            // ignore the SymUnloadModule64 error
        }

        // Rethrow the error

        throw;
    }
}


//
// Unload the symbol table for the file
//

Symbols::~Symbols()
{
    // Unload the symbol table

    try {
        dbghelp.SymUnloadModule64(symbols_base);
    }
    catch (DbgHelpError&) {
        // ignore the SymUnloadModule64 error
    }
}


//
// Adds a symbol to the array
//

void Symbols::add(SYMBOL_INFO *symbol_info)
{
    ea_t addr = (ea_t)symbol_info->Address;

    // adjust the address if it is relative to the image base
    if (addr >= symbols_base)
        addr = addr - (ea_t)symbols_base + image_base;

    Sym* sym = new Sym(symbol_info, addr);

    this->array.push_back(*sym);
}


//
// Returns the number of symbols in the array
//

unsigned int Symbols::num()
{
    return (unsigned int)this->array.size();
}


//
// Returns the symbol at a specified index (0..num()-1)
//

Sym* Symbols::get(unsigned int n)
{
    if (n >= this->array.size())
       return NULL;

    return &(this->array[n]);
}


//
// Apply all symbols
//

void Symbols::apply()
{
    int i;
    Sym* sym;

    // Iterators over the symbols array

    #define SYMBOLS_ITERATOR(sym, i)                               \
        for (i = 0, sym = &this->array[0];                         \
             i < (int)this->array.size();                          \
             i++, sym = &this->array[i])

    #define SYMBOLS_BACKWARDS_ITERATOR(sym, i)                     \
        for (i = (int)this->array.size()-1, sym = &this->array[i]; \
             i >= 0;                                               \
             i--, sym = &this->array[i])                           \

    // Pass 1: Rename all existing names in the database

    msg("pass 1: renaming existing names\n");

    SYMBOLS_ITERATOR(sym, i) {
        if (has_any_name(get_flags_novalue(sym->addr)) == true)
            sym->apply_name();
    }

    // Pass 2: Set all new names

    msg("pass 2: setting names\n");

    SYMBOLS_ITERATOR(sym, i) {
        if (has_any_name(get_flags_novalue(sym->addr)) == false)
            sym->apply_name();
    }

    // Pass 3: Create data items

    msg("pass 3: creating data items\n");

    SYMBOLS_ITERATOR(sym, i) {
        if (sym->type != SYM_FUNC)
            sym->apply();
    }

    // Pass 4: Create functions

    msg("pass 4: creating functions\n");

    SYMBOLS_BACKWARDS_ITERATOR(sym, i) {
        if (sym->type == SYM_FUNC)
            sym->apply();
    }

    #undef SYMBOLS_ITERATOR
    #undef SYMBOLS_BACKWARDS_ITERATOR
}


//
// Callback function for enumerating symbols from DbgHelp
//

BOOL CALLBACK Symbols::enum_symbols_proc(PSYMBOL_INFO pSymInfo,
                                         ULONG SymbolSize,
                                         PVOID UserContext)
{
    UNREFERENCED_PARAMETER(SymbolSize);

    // Get the Symbols object
    Symbols *symbols = (Symbols*)UserContext;

    // Add the symbol
    symbols->add(pSymInfo);

    return TRUE;
}


// ---------------------------------------------------------------------------
//
// List chooser UI that displays a list of symbols
//

class Chooser {

public:
    Symbols* symbols;

    // Initialize the chooser
    Chooser(Symbols* symbols) { this->symbols = symbols; }

    // Show the chooser UI
    unsigned int show();

    //
    // IDA callback functions
    //

    // Returns the number of items in the list
    static ulong idaapi ida_sizer(void* obj);

    // Returns the column values for the n-th item (1..n)
    static void idaapi ida_getl(void* obj, ulong n, char* const *arrptr);

    // Returns the icon number for the n-th item
    static int idaapi ida_get_icon(void* obj, ulong n);
};


//
// Show the chooser UI, returns the index of the selected element or 0 if
// the Cancel button was pressed
//

unsigned int Chooser::show()
{

#ifdef __EA64__
    int col_widths[3] = { 60, 10, 16 }; // more space for 64 bit addresses
#else
    int col_widths[3] = { 60, 10, 8 };
#endif

    int result = choose2(
        CH_MODAL,                       // flags
        -1, -1, -1, -1,                 // position
        this,                           // object
        3,                              // columns
        col_widths,                     // width of columns
        &Chooser::ida_sizer,            // sizer callback
        &Chooser::ida_getl,             // getl callback
        "Load Debugging Symbols",       // title
        -1,                             // default icon number
        1,                              // starting item
        NULL,                           // del callback
        NULL,                           // ins callback
        NULL,                           // update callback
        NULL,                           // edit callback
        NULL,                           // enter callback
        NULL,                           // destroy callback
        NULL,                           // popup names
        &Chooser::ida_get_icon);        // get_icon callback

    return result;
}


//
// Returns the number of items in the list
//

ulong idaapi Chooser::ida_sizer(void* obj)
{
    Chooser* chooser = (Chooser*)obj;

    return chooser->symbols->num();
}


//
// Returns the column values for the n-th item (1..n)
//

void idaapi Chooser::ida_getl(void* obj, ulong n, char* const *arrptr)
{
    Chooser* chooser = (Chooser*)obj;

    // If n is 0, return the list header

    if (n == 0) {
        qstrncpy(arrptr[0], "Symbol", MAXSTR);
        qstrncpy(arrptr[1], "Type", MAXSTR);
        qstrncpy(arrptr[2], "Address", MAXSTR);

        return;
    }

    // Get the Sym object

    Sym* sym = chooser->symbols->get(n-1);

    if (sym == NULL) {
        msg("ERROR: ida_getl callback called on a non-existent item %d\n", n);

        qstrncpy(arrptr[0], "", MAXSTR);
        qstrncpy(arrptr[1], "", MAXSTR);
        qstrncpy(arrptr[2], "", MAXSTR);

        return;
    }

    // Show the demangled name in the first column, if available

    if (sym->demangled_name != NULL)
        qsnprintf(arrptr[0], MAXSTR, "%s", sym->demangled_name);
    else
        qsnprintf(arrptr[0], MAXSTR, "%s", sym->symbol_info->Name);

    // Show the type in the second column

    switch (sym->type) {
        case SYM_FLOAT:
            qstrncpy(arrptr[1], "Float", MAXSTR);
            break;

        case SYM_DOUBLE:
            qstrncpy(arrptr[1], "Double", MAXSTR);
            break;

        case SYM_STRING:
            qstrncpy(arrptr[1], "String", MAXSTR);
            break;

        case SYM_FUNC:
            qstrncpy(arrptr[1], "Function", MAXSTR);
            if (sym->fpo != NULL)
                qstrncat(arrptr[1], " (FPO)", MAXSTR);
            break;

        case SYM_IMPORT:
            qstrncpy(arrptr[1], "Import", MAXSTR);
            break;

        case SYM_VTABLE:
            qstrncpy(arrptr[1], "Vtable", MAXSTR);
            break;

        case SYM_DATA:
            qstrncpy(arrptr[1], "Data", MAXSTR);
            break;

        case SYM_GUID:
            qstrncpy(arrptr[1], "GUID", MAXSTR);
            break;

        case SYM_UNKNOWN:
            qstrncpy(arrptr[1], "Unknown", MAXSTR);
            break;

        default:
            msg("ERROR: Unknown symbol type %d\n", sym->type);
            qstrncpy(arrptr[1], "", MAXSTR);
            break;
    }

    // Show the address in the third column

    qsnprintf(arrptr[2], MAXSTR, "%08a", (ea_t)sym->symbol_info->Address);
}


//
// Returns the icon number for the n-th item
//
// Icon numbers:
//
//     -2 - blank
//     -1 - IDA icon
//     0 - "s"
//     13 - f
//     26 - S
//     28 - U
//     41 - functions window icon
//     74 - C
//     75 - I
//     76 - A
//     79 - D
//     80 - "..."
//     81 - F
//    135 - exports icon
//    136 - imports icon
//

int idaapi Chooser::ida_get_icon(void* obj, ulong n)
{
    Chooser* chooser = (Chooser*)obj;

    // Chooser window icon

    if (n == 0)
        return -1;

    // Get the Sym object

    Sym* sym = chooser->symbols->get(n-1);

    if (sym == NULL) {
        msg("ERROR: ida_get_icon callback called on a non-existent item %d\n", n);
        return -2;
    }

    switch (sym->type) {
        case SYM_FLOAT:     return 79;  // D
        case SYM_DOUBLE:    return 79;  // D
        case SYM_STRING:    return 80;  // "..."
        case SYM_FUNC:      return 81;  // F
        case SYM_IMPORT:    return 136; // imports icon
        case SYM_VTABLE:    return 41;  // functions window icon
        case SYM_DATA:      return 79;  // D
        case SYM_GUID:      return 79;  // D
        case SYM_UNKNOWN:   return 28;  // U
    }

    return -2;
}


// ---------------------------------------------------------------------------
//
// Plugin interface
//


//
// Initialize plugin
//

int idaapi detpdb_init(void)
{
    const char *opts = get_plugin_options("pdb");

    if (opts != NULL && strcmp(opts, "off") == 0 )
        return PLUGIN_SKIP;     // Abort if the plugin is disabled

    if (inf.filetype != f_PE)
        return PLUGIN_SKIP;     // Abort if this is not a PE file

    return PLUGIN_KEEP;
}


//
// DbgHelp options, set by detpdb_parse_options
//

DWORD dbghelp_options = SYMOPT_EXACT_SYMBOLS;
char* dbghelp_symbol_path = NULL;


//
// Callback for parsing the config file
//

const char* idaapi detpdb_parse_options(const char *keyword,
                                        int value_type,
                                        const void *value)
{
    if (strcmp(keyword, "DETPDB_SYMBOL_PATH") == 0) {

        if (value_type != IDPOPT_STR)
            return IDPOPT_BADTYPE;

        // Set the DbgHelp search path
        dbghelp_symbol_path = qstrdup((const char*)value);
    }
    else if (strcmp(keyword, "DETPDB_DEBUG") == 0) {

        if (value_type != IDPOPT_BIT)
            return IDPOPT_BADTYPE;

        // Enable DbgHelp debugging
        if (*(int*)value == 1)
            dbghelp_options = dbghelp_options | SYMOPT_DEBUG;
    }
    else {
        return IDPOPT_BADKEY;
    }

    return IDPOPT_OK;
}


//
// Invoke plugin
//

void idaapi detpdb_run(int arg)
{
    UNREFERENCED_PARAMETER(arg);

    char input_file[MAXSTR];
    int len;

    msg(PLUGIN_NAME "\n");

    // Get the input file path

    len = get_input_file_path(input_file, sizeof(input_file));
    if (len == -1) {
        msg("ERROR: Could not get the path of the input file.\n");
        return;
    }

    if (len > sizeof(input_file)) {
        msg("ERROR: Input file name too long.\n");
        return;
    }

    // Get the image base

    netnode penode("$ PE header");
    ea_t image_base = penode.altval(PE_ALT_IMAGEBASE);

    // Get the PE header, which can be of type peheader_t or peheader64_t. We
    // need to ensure that the magic field is at the same offset in both.

#pragma warning(disable:4127)   // conditional expression is constant

    if (sizeof(peheader64_t) <= sizeof(peheader_t) ||
        qoffsetof(peheader_t, magic) != qoffsetof(peheader64_t, magic))
    {
        msg("ERROR: peheader_t and peheader64_t structures don't match.\n");
        return;
    }

#pragma warning(default:4127)

    peheader_t pe;

    if (penode.valobj(&pe, sizeof(pe)) != sizeof(pe)) {
        msg("ERROR: Failed to get PE header structure.\n");
        return;
    }

    // Get the options from the configuration file

    read_user_config_file("detpdb", detpdb_parse_options);

    // Initialize the DbgHelp API

    DbgHelp dbghelp;

    dbghelp.SymSetOptions(dbghelp_options);
    dbghelp.SymSetSearchPath(dbghelp_symbol_path);

    // Get the symbols

    Symbols* symbols;

    try {
        symbols = new Symbols(input_file, image_base);
    }
    catch (Error& error) {
        error.msg();    // show the error message
        return;
    }

    // Show the chooser UI

    Chooser* chooser = new Chooser(symbols);

    try {
        if (chooser->show() > 0) {

            // Load the Visual C++ type library

            // TODO: should we load more type libraries?

            if (ph.id == PLFM_386) {
                add_til(pe.is_pe_plus() ? "vc8amd64" : "vc6win");
            }

            // Apply the symbols to the database

            symbols->apply();

            msg("Loading completed\n");
        }
        else {
            msg("Loading canceled\n");
        }
    }
    catch (Error& error) {
        error.msg();    // show the error message
    }

    delete chooser;
    delete symbols;

    return;
}


//
// Plugin description strings
//

char detpdb_comment[] = PLUGIN_NAME;

char detpdb_help[] =
    PLUGIN_NAME "\n";;

char detpdb_wanted_name[] = PLUGIN_NAME;
char detpdb_wanted_hotkey[] = "Ctrl-4";


//
// Plugin description
//

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MOD | PLUGIN_UNL,    // plugin flags
    detpdb_init,                // initialize
    NULL,                       // terminate
    detpdb_run,                 // invoke plugin
    detpdb_comment,             // long comment about the plugin
    detpdb_help,                // multiline help about the plugin
    detpdb_wanted_name,         // the preferred short name of the plugin
    detpdb_wanted_hotkey        // the preferred hotkey to run the plugin
};
