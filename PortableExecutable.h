#ifndef PORTABLE_EXECUTABLE_HEADER
#define PORTABLE_EXECUTABLE_HEADER

#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>

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
#define EXECUTABLE_SECTION_HEADER_NO_PAD				0x00000008
#define EXECUTABLE_SECTION_HEADER_CODE					0x00000020
#define EXECUTABLE_SECTION_HEADER_INITIALIZED_DATA		0x00000040
#define EXECUTABLE_SECTION_HEADER_UNINITIALIZED_DATA	0x00000080
#define EXECUTABLE_SECTION_HEADER_OTHER					0x00000100
#define EXECUTABLE_SECTION_HEADER_INFO					0x00000200
#define EXECUTABLE_SECTION_HEADER_REMOVE				0x00000800
#define EXECUTABLE_SECTION_HEADER_COMDAT				0x00001000
#define EXECUTABLE_SECTION_HEADER_NO_DEFER_SPEC_EXC		0x00004000
#define EXECUTABLE_SECTION_HEADER_SHORT					0x00008000
#define EXECUTABLE_SECTION_HEADER_PURGEABLE				0x00020000
#define EXECUTABLE_SECTION_HEADER_LOCKED				0x00040000
#define EXECUTABLE_SECTION_HEADER_PRELOAD				0x00080000
#define EXECUTABLE_SECTION_HEADER_EXTENDED_RELOCATIONS	0x01000000
#define EXECUTABLE_SECTION_HEADER_DISCARDABLE			0x02000000
#define EXECUTABLE_SECTION_HEADER_NOT_CACHED			0x04000000
#define EXECUTABLE_SECTION_HEADER_NOT_PAGED				0x08000000
#define EXECUTABLE_SECTION_HEADER_SHARED				0x10000000
#define EXECUTABLE_SECTION_HEADER_EXECUTE				0x20000000
#define EXECUTABLE_SECTION_HEADER_READ					0x40000000
#define EXECUTABLE_SECTION_HEADER_WRITE					0x80000000
};

struct Section
{
	unsigned char * Data;
	unsigned long Length;
};

#define DOS_HEADER			0x00000001
#define FILE_HEADER			0x00000002
#define OPTIONAL_HEADER		0x00000004
#define SECTION_HEADER		0x00000008
#define SECTION_DATA		0x00000010

class PortableExecutable
{
public:
	PortableExecutable(std::string);
	~PortableExecutable();
	void Parse();
	void SetFilename(std::string);
	void Save();
	void SaveAs(std::string);
	void PrintHeader(int);
	std::string GetHeader(int);
	int NumberOfSections();
	Section GetSection(std::string);
	int GetSectionNumber(std::string);

private:
	std::string filename;
	EXECUTABLE_DOS_HEADER dosHeader;
	EXECUTABLE_FILE_HEADER fileHeader;
	EXECUTABLE_OPTIONAL_HEADER optionalHeader;
	EXECUTABLE_SECTION_HEADER * sectionHeaders;
	unsigned char * DOSProgram;
	Section * sections;
};

PortableExecutable::PortableExecutable(std::string filename)
{
	this->filename = filename;
}
PortableExecutable::~PortableExecutable()
{
	delete[] this->DOSProgram;
	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
		delete[] this->sections[i].Data;
	delete[] this->sectionHeaders;
	delete[] this->sections;
}
void PortableExecutable::Parse()
{
	std::ifstream ifile(this->filename, std::ios::binary);

	ifile.read((char *)&this->dosHeader, sizeof(EXECUTABLE_DOS_HEADER));

	this->DOSProgram = new unsigned char[this->dosHeader.AddressOfNewEXEHeader - sizeof(EXECUTABLE_DOS_HEADER)];

	ifile.read((char *)this->DOSProgram, this->dosHeader.AddressOfNewEXEHeader - sizeof(EXECUTABLE_DOS_HEADER));

	ifile.read((char *)&this->fileHeader, sizeof(EXECUTABLE_FILE_HEADER));

	ifile.read((char *)&this->optionalHeader, sizeof(EXECUTABLE_OPTIONAL_HEADER));

	this->sectionHeaders = new EXECUTABLE_SECTION_HEADER[this->fileHeader.NumberOfSections];

	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
		ifile.read((char *)&this->sectionHeaders[i], sizeof(EXECUTABLE_SECTION_HEADER));

	this->sections = new Section[this->fileHeader.NumberOfSections];

	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
	{
		this->sections[i].Data = new unsigned char[this->sectionHeaders[i].SizeOfRawData];
		this->sections[i].Length = this->sectionHeaders[i].SizeOfRawData;
		int j = 0;
		ifile.seekg(this->sectionHeaders[i].PointerToRawData);
		while (ifile.tellg() < this->sectionHeaders[i].PointerToRawData + this->sectionHeaders[i].SizeOfRawData)
			ifile.read((char *)&this->sections[i].Data[j++], sizeof(unsigned char));
	}
}
void PortableExecutable::SetFilename(std::string filename)
{
	this->filename = filename;
}
void PortableExecutable::Save()
{
	this->SaveAs(this->filename);
}
void PortableExecutable::SaveAs(std::string filename)
{
	std::ofstream ofile(filename, std::ios::binary);

	ofile.write((char *)&this->dosHeader, sizeof(EXECUTABLE_DOS_HEADER));

	ofile.write((char *)this->DOSProgram, this->dosHeader.AddressOfNewEXEHeader - sizeof(EXECUTABLE_DOS_HEADER));

	ofile.write((char *)&this->fileHeader, sizeof(EXECUTABLE_FILE_HEADER));

	ofile.write((char *)&this->optionalHeader, sizeof(EXECUTABLE_OPTIONAL_HEADER));

	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
		ofile.write((char *)&this->sectionHeaders[i], sizeof(EXECUTABLE_SECTION_HEADER));

	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
	{
		int j = 0;
		ofile.seekp(this->sectionHeaders[i].PointerToRawData);
		while (ofile.tellp() < this->sectionHeaders[i].PointerToRawData + this->sectionHeaders[i].SizeOfRawData)
			ofile.write((char *)&this->sections[i].Data[j++], sizeof(unsigned char));
	}
}
void PortableExecutable::PrintHeader(int header)
{
	std::cout << this->GetHeader(header);
}
std::string PortableExecutable::GetHeader(int header)
{
	std::stringstream ss;
	int section = (header >> 16) & 0xFFFF;
	if (header & DOS_HEADER)
	{
		ss << "Dos Header:" << std::endl;
		ss << std::endl;
		ss << "MagicNumber:                 " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.MagicNumber << std::endl;
		ss << "UsedBytesInTheLastPage:      " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.UsedBytesInTheLastPage << std::endl;
		ss << "FileSizeInPages:             " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.FileSizeInPages << std::endl;
		ss << "NumberOfRelocationItems:     " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.NumberOfRelocationItems << std::endl;
		ss << "HeaderSizeInParagraphs:      " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.HeaderSizeInParagraphs << std::endl;
		ss << "MinimumExtraParagraphs:      " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.MinimumExtraParagraphs << std::endl;
		ss << "MaximumExtraParagraphs:      " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.MaximumExtraParagraphs << std::endl;
		ss << "InitialRelativeSS:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.InitialRelativeSS << std::endl;
		ss << "InitialSP:                   " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.InitialSP << std::endl;
		ss << "Checksum:                    " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.Checksum << std::endl;
		ss << "InitialIP:                   " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.InitialIP << std::endl;
		ss << "InitialRelativeCS:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.InitialRelativeCS << std::endl;
		ss << "AddressOfRelocationTable:    " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.AddressOfRelocationTable << std::endl;
		ss << "OverlayNumber:               " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.OverlayNumber << std::endl;
		ss << "OEMID:                       " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.OEMID << std::endl;
		ss << "OEMInfo:                     " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.OEMInfo << std::endl;
		ss << "AddressOfNewEXEHeader:       " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->dosHeader.AddressOfNewEXEHeader << std::endl;
		ss << std::endl;
	}
	if (header & FILE_HEADER)
	{
		ss << "File Header:" << std::endl;
		ss << std::endl;
		ss << "FileType:                    " << (unsigned char *)&this->fileHeader.FileType << std::endl;
		ss << "Machine:                     " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.Machine << std::endl;
		ss << "NumberOfSections:            " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.NumberOfSections << std::endl;
		ss << "TimeDateStamp:               " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.TimeDateStamp << std::endl;
		ss << "PointToSymbolTable:          " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.PointToSymbolTable << std::endl;
		ss << "NumberOfSymbols:             " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.NumberOfSymbols << std::endl;
		ss << "SizeOfOptionalHeader:        " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.SizeOfOptionalHeader << std::endl;
		ss << "Characteristics:             " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->fileHeader.Characteristics << std::endl;
		ss << std::endl;
	}
	if (header & OPTIONAL_HEADER)
	{
		ss << "Optional Header:" << std::endl;
		ss << std::endl;
		ss << "MagicNumber:                 " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.Magic << std::endl;
		ss << "MajorLinkerVersion:          " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MajorLinkerVersion << std::endl;
		ss << "MinorLinkerVersion:          " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MinorLinkerVersion << std::endl;
		ss << "SizeOfCode:                  " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfCode << std::endl;
		ss << "SizeOfInitializedData:       " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfInitializedData << std::endl;
		ss << "SizeOfUnInitializedData:     " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfUninitializedData << std::endl;
		ss << "AddressOfEntryPoint:         " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.AddressOfEntryPoint << std::endl;
		ss << "BaseOfCode:                  " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.BaseOfCode << std::endl;
		ss << "BaseOfData:                  " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.BaseOfData << std::endl;
		ss << "ImageBase:                   " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.ImageBase << std::endl;
		ss << "SectionAlignment:            " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SectionAlignment << std::endl;
		ss << "FileAlignment:               " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.FileAlignment << std::endl;
		ss << "MajorOperatingSystemVersion: " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MajorOperatingSystemVersion << std::endl;
		ss << "MinorOperatingSystemVersion: " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MinorOperatingSystemVersion << std::endl;
		ss << "MajorImageVersion:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MajorImageVersion << std::endl;
		ss << "MinorImageVersion:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MinorImageVersion << std::endl;
		ss << "MajorSubsystemVersion:       " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MajorSubsystemVersion << std::endl;
		ss << "MinorSubsystemVersion:       " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.MinorImageVersion << std::endl;
		ss << "SizeOfImage:                 " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfImage << std::endl;
		ss << "SizeOfHeaders:               " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfHeaders << std::endl;
		ss << "Checksum:                    " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.CheckSum << std::endl;
		ss << "DllCharacteristics:          " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.DllCharacteristics << std::endl;
		ss << "SizeOfStackReserve:          " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfStackReserve << std::endl;
		ss << "SizeOfStackCommit:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfStackCommit << std::endl;
		ss << "SizeOfHeapReserve:           " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfHeapReserve << std::endl;
		ss << "SizeOfHeapCommit:            " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.SizeOfHeapCommit << std::endl;
		ss << "LoaderFlags:                 " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->optionalHeader.LoaderFlags << std::endl;
		ss << std::endl;
	}
	if (header & SECTION_HEADER)
	{
		ss << "Section #" << section + 1 << ": " << std::endl;
		ss << std::endl;
		ss << "Name:                        " << this->sectionHeaders[section].Name << std::endl;
		ss << "VirtualSize:                 " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].VirtualSize << std::endl;
		ss << "VirtualAddress:              " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].VirtualAddress << std::endl;
		ss << "SizeOfRawData:               " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].SizeOfRawData << std::endl;
		ss << "PointerToRawData:            " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].PointerToRawData << std::endl;
		ss << "PointerToRelocations:        " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].PointerToRelocations << std::endl;
		ss << "PointerToLineNumbers:        " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].PointerToLineNumbers << std::endl;
		ss << "NumberOfRelocations:         " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].NumberOfRelocations << std::endl;
		ss << "NumberOfLineNumbers:         " << std::hex << "0x"; ss.width(8); ss.fill('0'); ss << (unsigned long)this->sectionHeaders[section].NumberOfLineNumbers << std::endl;
		ss << "Characteristics:             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_NO_PAD)
			ss << "No Pad" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_CODE)
			ss << "Code" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_INITIALIZED_DATA)
			ss << "Initialized Data" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_UNINITIALIZED_DATA)
			ss << "Uninitialized Data" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_OTHER)
			ss << "Other" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_INFO)
			ss << "Info" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_REMOVE)
			ss << "Remove" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_COMDAT)
			ss << "COMDAT" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_NO_DEFER_SPEC_EXC)
			ss << "No Defer Spec Exc" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_SHORT)
			ss << "Short" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_PURGEABLE)
			ss << "Purgeable" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_LOCKED)
			ss << "Locked" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_PRELOAD)
			ss << "Preload" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_EXTENDED_RELOCATIONS)
			ss << "Extended Relocations" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_DISCARDABLE)
			ss << "Discardable" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_NOT_CACHED)
			ss << "Not Cached" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_NOT_PAGED)
			ss << "Not Paged" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_SHARED)
			ss << "Shared" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_EXECUTE)
			ss << "Execute" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_READ)
			ss << "Read" << std::endl << "                             ";
		if (this->sectionHeaders[section].Characteristics & EXECUTABLE_SECTION_HEADER_WRITE)
			ss << "Write" << std::endl << "                             ";
		ss << std::endl;
	}
	if (header & SECTION_DATA)
	{
		int numberOfLines;

		numberOfLines = this->sectionHeaders[section].VirtualSize / 16;
		if (this->sectionHeaders[section].VirtualSize % 16 != 0)
			numberOfLines++;

		ss << "Virtual Data: " << std::endl;
		ss << std::endl;
		for (int i = 0; i < (numberOfLines * 16); i++)
		{
			if (i % 16 == 0)
			{
				ss << "0x";
				ss.width(8);
				ss.fill('0');
				ss << std::hex << this->sectionHeaders[section].VirtualAddress + i << "  ";
			}
			if ((i + 1) % 16 == 0)
			{
				if (i < (int)this->sectionHeaders[section].VirtualSize && i < (int)this->sectionHeaders[section].SizeOfRawData)
				{
					ss.width(2);
					ss.fill('0');
					ss << std::hex << (int)this->sections[section].Data[i] << "  ";
				}
				else if (i < (int)this->sectionHeaders[section].VirtualSize && i >= (int)this->sectionHeaders[section].SizeOfRawData)
					ss << "UU  ";
				else
					ss << "    ";
				for (int j = (i + 1) - 16; j < (i + 1); j++)
					if (j < (int)this->sectionHeaders[section].VirtualSize && j < (int)this->sectionHeaders[section].SizeOfRawData)
						if (this->sections[section].Data[j] > 32 && this->sections[section].Data[j] < 127)
							ss << this->sections[section].Data[j];
						else
							ss << ".";
					else if (j < (int)this->sectionHeaders[section].VirtualSize && j >= (int)this->sectionHeaders[section].SizeOfRawData)
						ss << ".";
					else
						ss << " ";
				ss << std::endl;
			}
			else if ((i + 1) % 8 == 0)
			{
				if (i < (int)this->sectionHeaders[section].VirtualSize && i < (int)this->sectionHeaders[section].SizeOfRawData)
				{
					ss.width(2);
					ss.fill('0');
					ss << std::hex << (int)this->sections[section].Data[i] << "  ";
				}
				else if (i < (int)this->sectionHeaders[section].VirtualSize && i >= (int)this->sectionHeaders[section].SizeOfRawData)
					ss << "UU  ";
				else
					ss << "    ";
			}
			else
			{
				if (i < (int)this->sectionHeaders[section].VirtualSize && i < (int)this->sectionHeaders[section].SizeOfRawData)
				{
					ss.width(2);
					ss.fill('0');
					ss << std::hex << (int)this->sections[section].Data[i] << " ";
				}
				else if (i < (int)this->sectionHeaders[section].VirtualSize && i >= (int)this->sectionHeaders[section].SizeOfRawData)
					ss << "UU ";
				else
					ss << "   ";
			}
		}
		ss << std::endl;
	}
	return ss.str();
}
int PortableExecutable::NumberOfSections()
{
	return this->fileHeader.NumberOfSections;
}
Section PortableExecutable::GetSection(std::string sectionName)
{
	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
		if (std::string((char *)this->sectionHeaders[i].Name) == sectionName)
			return this->sections[i];
}
int PortableExecutable::GetSectionNumber(std::string sectionName)
{
	for (int i = 0; i < this->fileHeader.NumberOfSections; i++)
		if (std::string((char *)this->sectionHeaders[i].Name) == sectionName)
			return i;
	return 0xFFFFFFFF;
}

#endif