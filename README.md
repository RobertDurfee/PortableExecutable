# PortableExecutable
C++ class for parsing Windows portable executables.

### Disclaimer
This is not production-worthy code! View this simply as a proof-of-concept. Preconditions are implicit. No error checking exists.

### Initialization
```C++
PortableExecutable();
PortableExecutable(string filename);
```
A `PortableExecutable` can be constructed two different ways:

 1. By default, where nothing is initialized and the `Open` method must be called.
 2. With a filename which will be automatically parsed upon execution.
 
If the user wants to hold off on parsing the file, the first constructor can be used. Be aware that parsing may take awhile and may fail if the file is too big.

### Open
```C++
void Open(string filename);
```
If the default constructor was called and a file has not been parsed yet, this method will do so. The filename must be the name of a Windows x86 portable executable or `.exe` file. (This code may be compiler-specific as structures were filled not on a field-by-field basis so structure padding may result in error.)

### Save
```C++
void Save(string filename);
```
If alterations were made to the headers or section data, this method can be called to save the new portable executable. (This code may be compiler-specific as structures were filled not on a field-by-field basis so structure padding may result in error.)

### String Representation
```C++
string ToString(int command = (0x00 << 24) | (0xFF << 16) | DOS_HEADER | FILE_HEADER | OPTIONAL_HEADER | SECTION_HEADER | SECTION_DATA);
```
This method outputs a formatted string of the requested headers and/or section data. The `dosHeader`, `fileHeader`, and `optionalHeader` can be accessed by logical `OR`ing their respective constants to `command`. If `sectionHeaders` or `sectionData` is wanted, logical `OR` their respecitve constants and specify the first section in the bits 24 - 31 and the last section in the bits 16 - 23 of `command`. If only one section is needed, set both bit ranges to the same section. Also, if the last section desired is the last section available, the 16 - 23 bits of command to `0xFF`. By default, all headers and section data are included in the output.

### Accessing Headers
```C++
void * GetHeader(int command);
```
Using a similar command structure in `ToString` except only one constant can be used at a time. DO NOT LOGICAL `OR` CONSTANTS TOGETHER! If a section header is requested, the number of the section should be in bits 16 - 31 in `command`. The pointer returned by this method is the actual header contained in the `PortableExecutable` so alter with caution.

### Accessing Sections
```C++
Section * GetSection(int sectionNumber);
Section * GetSection(string sectionName);
int GetSectionNumber(string sectionName);
```
By specifying either a `sectionNumber` (starting at `0`) or a `sectionName`, a user can gain access to the section data contained in the `PortableExecutable`. If the `sectionNumber` is unknown but desired, use the `GetSectionNumber` method by supplying the name of the section.  The pointer returned by this method is the actual section data contained in the `PortableExecutable` so alter with caution.

### Deinitialization
```C++
~PortableExecutable();
```
Several variables are allocated dynamically as the program parses an executable. These must be freed in the destructor to prevent memory leaks.

### Structures
```C++
struct EXECUTABLE_DOS_HEADER
{
	unsigned short MagicNumber;
	unsigned short UsedBytesInTheLastPage;
	unsigned short FileSizeInPages;
	unsigned short NumberOfRelocationItems;
	unsigned short HeaderSizeInParagraphs;
	unsigned short MinimumExtraParagraphs;
	unsigned short MaximumExtraParagraphs;
	unsigned short InitialRelativeSS;
	unsigned short InitialSP;
	unsigned short Checksum;
	unsigned short InitialIP;
	unsigned short InitialRelativeCS;
	unsigned short AddressOfRelocationTable;
	unsigned short OverlayNumber;
	unsigned short Reserved1[4];
	unsigned short OEMID;
	unsigned short OEMInfo;
	unsigned short Reserved2[10];
	unsigned long AddressOfNewEXEHeader;
};

struct EXECUTABLE_FILE_HEADER
{
	unsigned long FileType;
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned long TimeDateStamp;
	unsigned long PointToSymbolTable;
	unsigned long NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
};

struct EXECUTABLE_DATA_DIRECTORY
{
	unsigned long VirtualAddress;
	unsigned long Size;
};

struct EXECUTABLE_OPTIONAL_HEADER
{
	unsigned short Magic;
	unsigned char MajorLinkerVersion;
	unsigned char MinorLinkerVersion;
	unsigned long SizeOfCode;
	unsigned long SizeOfInitializedData;
	unsigned long SizeOfUninitializedData;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long BaseOfData;
	unsigned long ImageBase;
	unsigned long SectionAlignment;
	unsigned long FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned long Reserved;
	unsigned long SizeOfImage;
	unsigned long SizeOfHeaders;
	unsigned long CheckSum;
	unsigned short SubSystem;
	unsigned short DllCharacteristics;
	unsigned long SizeOfStackReserve;
	unsigned long SizeOfStackCommit;
	unsigned long SizeOfHeapReserve;
	unsigned long SizeOfHeapCommit;
	unsigned long LoaderFlags;
	unsigned long NumberOfDirectories;
	EXECUTABLE_DATA_DIRECTORY DataDirectory[16];
};

struct EXECUTABLE_SECTION_HEADER
{
	unsigned char Name[8];
	unsigned long VirtualSize;
	unsigned long VirtualAddress;
	unsigned long SizeOfRawData;
	unsigned long PointerToRawData;
	unsigned long PointerToRelocations;
	unsigned long PointerToLineNumbers;
	unsigned short NumberOfRelocations;
	unsigned short NumberOfLineNumbers;
	unsigned long Characteristics;
};

struct Section
{
	unsigned char * Data;
	unsigned long Length;
};
```
The first five structures are defined by Microsoft for Windows x86 portable executable files. For more information on these headers and their parameters, visit [this page](http://www.csn.ul.ie/~caolan/publink/winresdump/winresdump/doc/pefile2.html). The last structure holds the section data stored in the portable executable along with the size of the data.

### Example
```C++
#include "PortableExecutable.h"

int main()
{
	PortableExecutable pe("Test.exe");
	
	cout << pe.ToString();

	return 0;
}
```
Usage is incredibly simple. Here, the executable `Test.exe` is loaded and all headers and section data are printed to the standard output stream.
