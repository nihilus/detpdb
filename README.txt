Determina PDB plugin for IDA Pro

   by Alexander Sotirov <asotirov@determina.com>


This is a replacement for the IDA PDB plugin which significantly improves the
analysis of binaries with public debugging symbols. The distribution contains
source code under a BSD license and a binary for IDA Pro 5.0 and 5.1.


Compiling from source:

If you want to use the precompiled binary, skip to the next section. To compile
the plugin from source, you will need the following:

   GNU make from Cygwin
   Microsoft Visual C++ 2005
   Debugging Tools for Windows 6.7.5.0
   IDA Pro SDK 5.0 or 5.1

Edit the Makefile and set the IDASDK and DBGSDK variables. They need to point
to the directories containing the IDA SDK and the Debugging Tools for Windows
SDK. Make sure that the compiler is in your path and the INCLUDE and LIB
environment variables are set. Run make to compile the plugin.


Installation:

1) Make a backup copy of pdb.plw and pdb.p64 in your IDA plugins directory.

2) Copy plugin/plw/pdb.plw and plugin/p64/pdb.p64 to your IDA plugins
   directory, overwriting the existing files.

3) Copy detpdb.cfg to the IDA cfg directory.

3) Make sure that you have the latest versions of dbghelp.dll and symsrv.dll in
   your IDA directory. If they are older than 6.7.5.0, download the Debugging
   Tools for Windows from http://www.microsoft.com/whdc/devtools/debugging/
   and replace the files in the IDA directory with the latest versions.


Configuration:

The Determina PDB plugin uses the same method for finding symbol files as the
WinDbg debugger. By default, the plugin will search the current working
directory, followed by the symbol search path specified in the _NT_SYMBOL_PATH
and _NT_ALTERNATE_SYMBOL_PATH environmental variables.

The search path can also be specified by setting the DETPDB_SYMBOL_PATH option
in the detpdb.cfg configuration file.

For more information about the format of the symbol path and the environmental
variables, see the documentation included in the Debugging Tools for Windows.


Usage:

When loading a new file linked with debugging information, IDA will invoke
the Determina PDB plugin. If the corresponding symbol file is found in the
symbol path, the plugin will display the list of all available symbols and
their addresses. Press OK to load these symbols into the IDA database, or
Cancel to skip the symbol loading.

Once the IDA autoanalysis is finished, check the messages window for any
errors or warnings. You will probably see messages similar to:

   Name 'const GCObj::`vftable'' at 5A323BC0 is deleted...

These messages indicate that some names were deleted during the final analysis
pass. One solution is to disable the 'Make final analysis pass' options before
starting the analysis. A better alternative is to run the PDB plugin a second
time after the autoanalysis is finished, ensuring that the deleted names are
recreated.
