#include <io.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdio>
#include <windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace std;

#define PDB_SIGNATURE_700 \
    "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"

#define PDB_SIGNATURE_TEXT 32

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#pragma pack(1)
typedef struct _PDB_SIGNATURE
  {
  BYTE abSignature [PDB_SIGNATURE_TEXT]; // PDB_SIGNATURE_nnn
  }
  PDB_SIGNATURE, *PPDB_SIGNATURE, **PPPDB_SIGNATURE;

#define PDB_SIGNATURE_ sizeof (PDB_SIGNATURE)

// -----------------------------------------------------------------

#define PDB_STREAM_FREE -1

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef struct _PDB_STREAM
  {
  unsigned __int64 dStreamSize;  // in bytes, -1 = free stream
  DWORD PagesIndex; // page with with array of pages index
  }
  PDB_STREAM, *PPDB_STREAM, **PPPDB_STREAM;

#define PDB_STREAM_ sizeof (PDB_STREAM)

// -----------------------------------------------------------------

#define PDB_PAGE_SIZE_1K  0x0400 // bytes per page
#define PDB_PAGE_SIZE_2K  0x0800
#define PDB_PAGE_SIZE_4K  0x1000

#define PDB_PAGE_SHIFT_1K 10   // log2 (PDB_PAGE_SIZE_*)
#define PDB_PAGE_SHIFT_2K 11
#define PDB_PAGE_SHIFT_4K 12

#define PDB_PAGE_COUNT_1K 0xFFFF // page number < PDB_PAGE_COUNT_*
#define PDB_PAGE_COUNT_2K 0xFFFF
#define PDB_PAGE_COUNT_4K 0x7FFF

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef struct _PDB_HEADER
  {
  PDB_SIGNATURE Signature;   // PDB_SIGNATURE_200
  DWORD     dPageSize;   // 0x0400, 0x0800, 0x1000
  DWORD     wStartPage;   // 0x0009, 0x0005, 0x0002
  DWORD     wFilePages;   // file size / dPageSize
  DWORD     dwRootStreamSize;
  DWORD		unk1;
  DWORD		nRootPageIndex;
  }
  PDB_HEADER, *PPDB_HEADER, **PPPDB_HEADER;

#define PDB_HEADER_ sizeof (PDB_HEADER)

#define PDB_STREAM_DIRECTORY 0
#define PDB_STREAM_PDB    1
#define PDB_STREAM_PUBSYM  7

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

typedef struct _PDB_ROOT
  {
  WORD    wCount;   // < PDB_STREAM_MAX
  WORD    wReserved;  // 0
  DWORD	dwStreamSizes[1];
  }
  PDB_ROOT, *PPDB_ROOT, **PPPDB_ROOT;

#define PDB_ROOT_ sizeof (PDB_ROOT)

struct PDB_MODULES_HEADER
{
	unsigned int Unknown1;
	unsigned int Unknown2;
	unsigned int FileVersion;
	unsigned int Unknown3;
	unsigned int Unknown4;
	unsigned int Unknown5;
	unsigned int ModulesLength;
	unsigned int LengthSomeData1;
	unsigned int LengthSomeData2;
	unsigned int SourcesLength;
	unsigned int Unknown9;
	unsigned int UnknownA;
	unsigned int LengthSomeData4;
	unsigned int LengthSomeData3;
	unsigned int UnknownD;
	unsigned int UnknownE;
};

struct PDB_MODULE_HEADER
{
	unsigned int Unknown0;
	unsigned short Unknown4;
	unsigned short Unknown6;
	unsigned int Offset;
	unsigned int CodeSize;
	unsigned char Unknown10[4];
	unsigned short Unknown14;
	unsigned short Unknown16; // 0
	unsigned int CheckSum;
	unsigned int Unknown1C; // 0
	unsigned short Unknown1E; // 0
	unsigned short ModuleStream;
	unsigned int SymbolsLen;
	unsigned int Unknown28; // 0
	unsigned int LineNumbersLen; // 20 A8
	unsigned int SourcesNum;
	unsigned int Random34; // many
	unsigned int Unknown38; // 0
	unsigned int Unknown3C; // 0
};

#pragma pack(push)
#pragma pack(4)
struct PDB_SRCMOD_INFO
{
	WORD Unknown0;
	DWORD Offset;
	DWORD Size;
	DWORD UnknownC;
	WORD Unknown10;
	DWORD CheckSum;
	DWORD Unknown18;
};
#pragma pack(pop)

HANDLE PdbFile;
_PDB_HEADER PdbHeader;
DWORD * RootStreamPageIndex;
DWORD RootStreamNumPages;
_PDB_ROOT * RootStream;
DWORD * StreamsSizes;
DWORD * PagesIndexes;

struct Stream
{
	WORD streamNo;
	DWORD size;
	DWORD pos;
	DWORD firstPageIndex;
};

bool OpenStream(DWORD streamNo, Stream & stream)
{
	if (streamNo >= RootStream->wCount)
		return false;

	stream.streamNo = streamNo;
	stream.size = RootStream->dwStreamSizes[streamNo];
	DWORD index = 0;
	for (DWORD i = 0; i < streamNo; i++)
	{
		index += (RootStream->dwStreamSizes[i] + PdbHeader.dPageSize - 1) / PdbHeader.dPageSize;
	}
	stream.firstPageIndex = index;
	stream.pos = 0;
	return true;
}

DWORD ReadStream(Stream & stm, BYTE * buffer, DWORD cbSize)
{
	DWORD read = min(cbSize, stm.size - stm.pos);
	DWORD page = stm.pos / PdbHeader.dPageSize;
	DWORD pageOffset = stm.pos - page * PdbHeader.dPageSize;
	DWORD remains = read;
	BYTE * pos = buffer;
	while (remains != 0)
	{
		DWORD inPageSize = min(PdbHeader.dPageSize - pageOffset, remains);
		LARGE_INTEGER fpos;
		fpos.QuadPart = PagesIndexes[stm.firstPageIndex + page] * PdbHeader.dPageSize + pageOffset;
		DWORD fileRead;
		SetFilePointer(PdbFile, fpos.LowPart, &fpos.HighPart, FILE_BEGIN);
		ReadFile(PdbFile, pos, inPageSize, &fileRead, 0);
		pageOffset = 0;
		remains -= inPageSize;
		pos += inPageSize;
		page ++;
	}
	stm.pos += read;
	return read;
}

void DumpStreamToFile(Stream & stm, DWORD start, DWORD len, const char * filename)
{
	DWORD was = stm.pos;
	if (len == 0)
		len = stm.size;
	BYTE * buffer = new BYTE[len];
	stm.pos = start;
	ReadStream(stm, buffer, len);
	int f = _open(filename, _O_BINARY | _O_CREAT | _O_RDWR | _O_TRUNC, _S_IREAD | _S_IWRITE);
	int ires = _write(f, buffer, len);
	ires = _close(f);
	delete [] buffer;
	stm.pos = was;
}

void ReadZString(Stream & stm, string & str)
{
	str.clear();
	while (true)
	{
		char ch;
		ReadStream(stm, (PBYTE)&ch, 1);
		if (ch == 0)
			break;
		str.push_back(ch);
	}
}

struct Value
{
	enum Type { TYPE_WORD, TYPE_DWORD, };
	Type Type;
	union
	{
		WORD wVal;
		DWORD dwVal;
	};
};

void ReadValue(Stream & stm, Value & val)
{
	WORD w;
	ReadStream(stm, (PBYTE)&w, 2);
	if (w == 0x8004)
	{
		val.Type = val.TYPE_DWORD;
		ReadStream(stm, (PBYTE)&val.dwVal, 4);
	}
	else
	{
		val.Type = val.TYPE_WORD;
		val.wVal = w;
	}
}

void PrintValue(ostream & stm, Value & val)
{
	switch (val.Type)
	{
	case val.TYPE_WORD:
		stm << val.wVal;
		break;
	case val.TYPE_DWORD:
		stm << val.dwVal;
		break;
	default:
		throw 0;
	}
}

const char * AccessToStr(WORD access)
{
	switch (access)
	{
	case 1: return "private";
	case 2: return "protected";
	case 3: return "public";
	default: throw 0;
	}
}

const char * CallConvToStr(BYTE callConv)
{
	switch (callConv)
	{
	case 0: return "cdecl";
	case 4: return "fastcall";
	case 7: return "stdcall";
	case 11: return "thiscall";
	default: throw 0;
	}
}

const wchar_t * utf8towcs(const char * utf8)
{
		int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, 0, 0);
		if (len == 0)
			return 0;
		static vector<wchar_t> wcs;
		wcs.resize(len);
		if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &wcs[0], len) == 0)
			return 0;
		return &wcs[0];
}

const char * Canonicalize(const char * str)
{
	static string result;
	result.clear();
	for (const char * pos = str; *pos; pos++)
	{
		if (*pos == ':')
			result += "&colon;";
		else if (*pos == '&')
			result += "&amp;";
		else
			result += *pos;
	}
	return result.c_str();
}

template <class iterator>
void PrintBin(iterator from, iterator to)
{
	for (iterator pos = from; pos != to; pos++)
		cout << setfill('0') << setw(2) << (int)*pos << " ";
}

void PrintStream(Stream & stm, DWORD len)
{
	static vector<BYTE> buffer;
	buffer.resize(len);
	ReadStream(stm, &buffer[0], len);
	PrintBin(buffer.begin(), buffer.end());
}

// stream 1 matches against exe
/*
layout:
+0 unknown: 94 2E 31 01
+4 timestam: time_t - must match timestamp in exe
+8 version: incremented on each build
+C guid: GUID - must match guid in exe
+1C StrLen: DWORD - length of following z-ansi string
+20 String - list of zeroterminated ansi strings like:
	/LinkInfo
	/names
	/src/headerblock
+* array: DWORD[12] looks like array of stream indexes


mathing debug section in exe:
layout:
typedef struct _IMAGE_DEBUG_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Type;
  DWORD SizeOfData;
  DWORD AddressOfRawData;
  DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, 
 *PIMAGE_DEBUG_DIRECTORY;

IMAGE_DEBUG_TYPE_CODEVIEW	2
+1C 0: 4
+20 1: 4
+24 2: 4
+28 3: 4
+2C 4: 4
+30 403050: 4 - pointer to variable GS_ExceptionRecord
+34 4030A8: 4 - pointer to variable GS_ContextRecord
+38 48: 4
+3C 0: 0x38
+74 403010: 4 - pointer to __security_cookie
+78 4021D0: 4 - pointer to __safe_se_handler_table
+7C 1: 4

debug RVA:
+0 "RSDS" : 4 - Format ID
+4 guid: GUID must match guid in pdb file
+14 1: 4
+18 utf8 pdb file name
*/

// stream 2 = enums, structs, classes, union
// stream 8 = typedefs, functions, global/statics, public symbols
// and every obj file has its own stream
// stream 9 = segments schema
// stream 15 ... are for object files

void ParseTypesStream()
{
	Stream stm;
	OpenStream(2, stm);
	stm.pos = 0x38;
	DWORD typeID = 0x1000;
	for (; stm.pos != stm.size; typeID++)
	{
		DWORD unknown1;
		DWORD unknown2;
		BYTE callConv;
		DWORD returnTypeId;
		DWORD thisTypeId;
		DWORD argsTypeId;
		WORD itemSize;
		WORD itemType;
		string typeName;
		vector<BYTE> buffer;

		ReadStream(stm, (PBYTE)&itemSize, 2);
		DWORD itemStart = stm.pos;
		ReadStream(stm, (PBYTE)&itemType, 2);
		cout << typeID << ": ";
		switch (itemType)
		{
		case 0x1008:
			ReadStream(stm, (PBYTE)&returnTypeId, 4);
			ReadStream(stm, &callConv, 1);
			stm.pos += 3;
			ReadStream(stm, (PBYTE)&argsTypeId, 4);
			cout << "LF_PROCEDURE: return type = " << returnTypeId << "  call conv = " << CallConvToStr(callConv) << "  args type = " << argsTypeId;
			break;
		case 0x1009:
			ReadStream(stm, (PBYTE)&returnTypeId, 4);
			ReadStream(stm, (PBYTE)&thisTypeId, 4);
			ReadStream(stm, (PBYTE)&unknown1, 4);
			ReadStream(stm, &callConv, 1);
			stm.pos += 3; // 00 01 00
			ReadStream(stm, (PBYTE)&argsTypeId, 4);
			stm.pos += 4; // maybe this correction
			cout << "LF_MFUNCTION: return type = " << returnTypeId << "  call conv = " << CallConvToStr(callConv) <<
				"  args type = " << argsTypeId << "  this type = " << thisTypeId << "  unknown1 = " << unknown1;
			break;
		case 0x1201:
			DWORD numArgs;
			ReadStream(stm, (PBYTE)&numArgs, 4);
			cout << "LF_ARGLIST  num = " << numArgs << endl;
			for (DWORD i = 0; i < numArgs; i++)
			{
				DWORD argType;
				ReadStream(stm, (PBYTE)&argType, 4);
				cout << "  arg type = " << argType << endl;
			}
			break;
		case 0x1203:
			cout << "LF_LIST" << endl;
			while (stm.pos != itemStart + itemSize)
			{
				WORD memberType;
				Value value;
				WORD access;
				DWORD parentTypeId;
				WORD fieldOffset;
				ReadStream(stm, (PBYTE)&memberType, 2);
				switch (memberType)
				{
				case 0x1400:
					ReadStream(stm, (PBYTE)&access, 2);
					ReadStream(stm, (PBYTE)&parentTypeId, 4);
					ReadStream(stm, (PBYTE)&fieldOffset, 2);
					stm.pos = (stm.pos + 3) / 4 * 4;
					cout << "  parent: " << parentTypeId << "  access = " << AccessToStr(access) << "  this offset = " << fieldOffset;
					break;
				case 0x1409:
					unknown1 = 0;
					ReadStream(stm, (PBYTE)&unknown1, 2);
					ReadStream(stm, (PBYTE)&unknown2, 4);
					cout << "  maybe virtual table  unknown1 = " << unknown1 << "  unknown2 = " << unknown2;
					break;
				case 0x1502:
					stm.pos += 2;
					ReadValue(stm, value);
					ReadZString(stm, typeName);
					cout << "  enum item: " << typeName << "  value = ";
					PrintValue(cout, value);
					stm.pos = (stm.pos + 1) / 2 * 2;
					break;
				case 0x150D:
					ReadStream(stm, (PBYTE)&access, 2);
					DWORD fieldType;
					ReadStream(stm, (PBYTE)&fieldType, 4);
					ReadStream(stm, (PBYTE)&fieldOffset, 2);
					ReadZString(stm, typeName);
					stm.pos = (stm.pos + 3) / 4 * 4;
					cout << "  field: " << typeName << "  type = " << fieldType << "  offset = " << fieldOffset << "  access = " << AccessToStr(access);
					break;
				case 0x150E:
					ReadStream(stm, (PBYTE)&access, 2);
					ReadStream(stm, (PBYTE)&fieldType, 4);
					ReadZString(stm, typeName);
					stm.pos = (stm.pos + 3) / 4 * 4;
					cout << "  static field: " << typeName << "  type = " << fieldType << "  access = " << AccessToStr(access);
					break;
				case 0x150F:
					cout << "  maybe copy constructor" << endl;
					PrintStream(stm, 6);
					ReadZString(stm, typeName);
					cout << "   name = " << typeName;
					stm.pos = (stm.pos + 3) / 4 * 4;
					break;
				case 0x1510:
					stm.pos += 2;
					DWORD typeId;
					ReadStream(stm, (PBYTE)&typeId, 4);
					ReadZString(stm, typeName);
					cout << "  subtype: " << typeName << "  type = " << typeId;
					break;
				case 0x1511:
					ReadStream(stm, (PBYTE)&access, 2);
					ReadStream(stm, (PBYTE)&typeId, 4);
					if (access & 0x10)
						ReadStream(stm, (PBYTE)&unknown1, 4);
					ReadZString(stm, typeName);
					cout << "  method: " << typeName << "()  type = " << typeId << "  access = " << AccessToStr(access & 0x3);
					if (access & 0x10)
						cout << "  unknown1 = " << unknown1;
					stm.pos = (stm.pos + 3) / 4 * 4;
					break;
				default:
					cout << "  UNKNOWN MEMBER! " << memberType << " skipping remaining members if any";
					stm.pos = itemStart + itemSize;
					break;
				}
				cout << endl;
			}
			break;
		case 0x1504:
			cout << "class ";
			stm.pos += 0x12;
			while (true)
			{
				char ch;
				ReadStream(stm, (PBYTE)&ch, 1);
				if (ch == 0)
					break;
				typeName.push_back(ch);
			}
			cout << typeName;
			break;
		case 0x1505:
			cout << "struct ";
			stm.pos += 0x12;
			while (true)
			{
				char ch;
				ReadStream(stm, (PBYTE)&ch, 1);
				if (ch == 0)
					break;
				typeName.push_back(ch);
			}
			cout << typeName;
			break;
		case 0x1506:
			cout << "union";
			stm.pos += 0xA;
			while (true)
			{
				char ch;
				ReadStream(stm, (PBYTE)&ch, 1);
				if (ch == 0)
					break;
				typeName.push_back(ch);
			}
			cout << typeName;
			break;
		case 0x1507:
			cout << "enum ";
			stm.pos += 0xC;
			while (true)
			{
				char ch;
				ReadStream(stm, (PBYTE)&ch, 1);
				if (ch == 0)
					break;
				typeName.push_back(ch);
			}
			cout << typeName;
			break;
		default:
			cout << "unk type " << itemType << "  data:" << endl;
			buffer.resize(itemSize - stm.pos + itemStart);
			ReadStream(stm, &buffer[0], buffer.size());
			PrintBin(buffer.begin(), buffer.end());
			break;
		}
		cout << endl;
		stm.pos = itemStart + itemSize;
	}
}

struct ProcHeader
{
	DWORD Parent;
	DWORD End;
	DWORD Next;
	DWORD Length;
	DWORD DebugStart;
	DWORD DebugEnd;
	DWORD Type;
	DWORD Offset;
	BYTE UnknownFlags[3];
};

void ParseSymbols(Stream & stm, DWORD size)
{
	if (size == 0)
		return;
	string objname;
	string fnname;
	string varname;
	string compiler;
	string secname;
	stm.pos += 4;
	while (stm.pos != size)
	{
		WORD itemLen;
		cout << stm.pos << "\t";
		ReadStream(stm, (PBYTE)&itemLen, 2);
		DWORD itemStart = stm.pos;
		WORD itemType;
		ReadStream(stm, (PBYTE)&itemType, 2);
		switch (itemType)
		{
		case 0x6:
			cout << "S_END";
			break;
		case 0x1012:
			DWORD stackFrameSize;
			ReadStream(stm, (PBYTE)&stackFrameSize, 4);
			cout << "Stack frame size: " << stackFrameSize;
			break;
		case 0x1101:
			stm.pos += 4;
			ReadZString(stm, objname);
			wcout << L"S_OBJNAME: " << utf8towcs(objname.c_str());
			break;
		case 0x1102:
			cout << "unknown 1102" << endl;
			break;
		case 0x1103:
			DWORD parentOffset;
			ReadStream(stm, (PBYTE)&parentOffset, 4);
			DWORD endOffset;
			ReadStream(stm, (PBYTE)&endOffset, 4);
			cout << "S_BLOCK: parent = " << parentOffset << "  end = " << endOffset;
			break;
		case 0x1105:
			cout << "unknown 1105" << endl;
			break;
		case 0x1106:
			cout << "unknown 1106" << endl;
			break;
		case 0x1107:
			cout << "unknown 1107" << endl;
			break;
		case 0x1108:
			cout << "unknown 1108" << endl;
			break;
		case 0x110B:
			int bpoffset;
			ReadStream(stm, (PBYTE)&bpoffset, 4);
			DWORD type;
			ReadStream(stm, (PBYTE)&type, 4);
			ReadZString(stm, varname);
			cout << "S_BPREL [BP" << (bpoffset < 0 ? '-' : '+') << (bpoffset >= 0 ? bpoffset : -bpoffset) << "]: Type: 0x" << type << "; Name: " << varname;
			break;
		case 0x110C:
			cout << "unknown 110C" << endl;
			break;
		case 0x110F:
			cout << "unknown 110C" << endl;
			break;
		case 0x1110:
			ProcHeader procHeader;
			ReadStream(stm, (PBYTE)&procHeader, 0x23);
			ReadZString(stm, fnname);
			char filename[512];
			sprintf(filename, "fn%s.bin", Canonicalize(fnname.c_str()));
			cout << "S_PROC: " << fnname << "  rva = " << procHeader.Offset << "  size = " << procHeader.Length << "  end = " << procHeader.End << "  type = " << procHeader.Type;
			break;
		case 0x1116:
			stm.pos += 0x12;
			ReadZString(stm, compiler);
			cout << "S_COMPILER: " << compiler;
			break;
		case 0x112C:
			cout << "unknown 112C" << endl;
			break;
		case 0x1136:
			stm.pos += 0x8;
			DWORD sectionSize;
			ReadStream(stm, (PBYTE)&sectionSize, 4);
			stm.pos += 4;
			ReadZString(stm, secname);
			cout << "S_SECTION1: " << secname << "  size = " << sectionSize;
			break;
		case 0x1137:
			ReadStream(stm, (PBYTE)&sectionSize, 4);
			stm.pos += 0xA;
			ReadZString(stm, secname);
			cout << "S_SECTION2: " << secname << "  size = " << sectionSize;
			break;
		case 0x1139:
			cout << "unknown 1139" << endl;
			break;
		case 0x113A:
			cout << "unknown 113A" << endl;
			break;
		default:
			throw 0;
		}
		stm.pos = itemStart + itemLen;
		cout << endl;
	}
}

void ParseLineNumbers(Stream & stm, DWORD size)
{
	char filename[512];
	sprintf_s(filename, "srclnblock%d.bin", stm.streamNo);
	DumpStreamToFile(stm, stm.pos, stm.size - stm.pos, filename);
	DWORD start = stm.pos;
	while (stm.pos != start + size)
	{
		WORD itemType;
		ReadStream(stm, (PBYTE)&itemType, 2);
		switch (itemType)
		{
		case 0xF2: // line numbers
			stm.pos += 0x16;
			DWORD linesNo;
			ReadStream(stm, (PBYTE)&linesNo, 4);
			stm.pos += 4;
			for (DWORD l = 0; l < linesNo; l++)
			{
				DWORD offset;
				DWORD lineno;
				ReadStream(stm, (PBYTE)&offset, 4);
				ReadStream(stm, (PBYTE)&lineno, 4);
				lineno = lineno & 0x7fffffff;
				cout << "Line: " << lineno << "; Offset: " << offset << endl;
			}
			break;
		case 0xF4: // source hash
			stm.pos += 0x2;
			DWORD len;
			ReadStream(stm, (PBYTE)&len, 4);
			DWORD start;
			start = stm.pos;
			while (stm.pos != start + len)
			{
				DWORD nameOffset;
				ReadStream(stm, (PBYTE)&nameOffset, 4);
				stm.pos += 2;
			unsigned char hash[16];
			ReadStream(stm, (PBYTE)hash, 16);
				cout << "HASH: Name offset = " << (nameOffset - 2) << "  hash = {";
			cout.width(2);
			for (int i = 0; i < 16; i++)
			{
				cout << int(hash[i]) << ' ';
			}
				cout << "}" << endl;
				stm.pos += 2;
			}
			return;
		default:
			throw 0;
		}
	}
}

int main(int argc, const char * argv[])
{
	setlocale(LC_ALL, "");
	if (argc < 2)
		return 1;
	PdbFile = CreateFileA(argv[1], FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, 0);
	DWORD read;
	ReadFile(PdbFile, &PdbHeader, sizeof(PdbHeader), &read, 0);
	RootStreamNumPages = (PdbHeader.dwRootStreamSize + PdbHeader.dPageSize - 1) / PdbHeader.dPageSize;
	RootStreamPageIndex = new DWORD[RootStreamNumPages];
	LARGE_INTEGER fpos;
	fpos.QuadPart = PdbHeader.dPageSize * PdbHeader.nRootPageIndex;
	SetFilePointer(PdbFile, fpos.LowPart, &fpos.HighPart, FILE_BEGIN);
	ReadFile(PdbFile, RootStreamPageIndex, RootStreamNumPages * sizeof(DWORD), &read, 0);
	RootStream = reinterpret_cast<_PDB_ROOT *>(malloc(PdbHeader.dwRootStreamSize));
	DWORD remains = PdbHeader.dwRootStreamSize;
	BYTE * pos = reinterpret_cast<BYTE *>(RootStream);
	DWORD pageNo = 0;
	while (remains != 0)
	{
		DWORD blockSize = min(remains, PdbHeader.dPageSize);
		fpos.QuadPart = RootStreamPageIndex[pageNo] * PdbHeader.dPageSize;
		SetFilePointer(PdbFile, fpos.LowPart, &fpos.HighPart, FILE_BEGIN);
		ReadFile(PdbFile, pos, blockSize, &read, 0);
		pos += blockSize;
		remains -= blockSize;
		pageNo++;
	}
	PagesIndexes = &RootStream->dwStreamSizes[RootStream->wCount];
	for (int i = 0; i < RootStream->wCount; i++)
	{
		Stream stm;
		OpenStream(i, stm);
		if (stm.size == -1)
			continue;
		char name[20];
		sprintf_s(name, "stm%d.bin", i);
		DumpStreamToFile(stm, 0, 0, name);
	}

	cout << hex;
	wcout << hex;

	ParseTypesStream();

	Stream stm;
	OpenStream(3, stm);
	PDB_MODULES_HEADER modsHdr;
	ReadStream(stm, (BYTE*)&modsHdr, sizeof modsHdr);
	cout << "PDB version: " << modsHdr.FileVersion << endl;
	cout << "Modules size: " << modsHdr.ModulesLength << endl;
	cout << "Some size1: " << modsHdr.LengthSomeData1 << endl;
	cout << "Some size2: " << modsHdr.LengthSomeData2 << endl;
	cout << "Sources size: " << modsHdr.SourcesLength << endl;
	int moduleNumber = 0;
	while (stm.pos - 0x40 != modsHdr.ModulesLength)
	{
		DWORD moduleStart = stm.pos;

		PDB_MODULE_HEADER moduleHdr;
		ReadStream(stm, (PBYTE)&moduleHdr, sizeof moduleHdr);
		cout << "Offset: " << moduleHdr.Offset << endl;
		cout << "Size: " << moduleHdr.CodeSize << endl;
		cout << "Module stream: " << moduleHdr.ModuleStream << endl;
		cout << "Symbols length: " << moduleHdr.SymbolsLen << endl;
		cout << "Line numbers length: " << moduleHdr.LineNumbersLen << endl;
		cout << "Sources number: " << moduleHdr.SourcesNum << endl;

		string name1;
		ReadZString(stm, name1);
		wcout << utf8towcs(name1.c_str()) << endl;

		string name2;
		ReadZString(stm, name2);
		wcout << utf8towcs(name2.c_str()) << endl;

		stm.pos = ((stm.pos + 3) / 4) * 4;
		char filename[20];
		sprintf_s(filename, "mod%d.bin", moduleNumber);
		DumpStreamToFile(stm, moduleStart, stm.pos - moduleStart, filename);

		Stream modstm;
		OpenStream(moduleHdr.ModuleStream, modstm);
		ParseSymbols(modstm, moduleHdr.SymbolsLen);
		ParseLineNumbers(modstm, moduleHdr.LineNumbersLen);
		moduleNumber++;
	}

	DumpStreamToFile(stm, stm.pos, modsHdr.LengthSomeData1, "modulesarr.bin");

	DWORD start = stm.pos;
	stm.pos += 4;
	while (stm.pos != start + modsHdr.LengthSomeData1)
	{
		PDB_SRCMOD_INFO srcmod;
		ReadStream(stm, (PBYTE)&srcmod, sizeof srcmod);
		cout << srcmod.Offset << endl;
	}

	DumpStreamToFile(stm, stm.pos, modsHdr.LengthSomeData2, "somedata2.bin");
	stm.pos += modsHdr.LengthSomeData2;

	start = stm.pos;
	DumpStreamToFile(stm, stm.pos, modsHdr.SourcesLength, "sources.bin");
	WORD numModules;
	ReadStream(stm, (PBYTE)&numModules, 2);
	WORD numOffsets;
	ReadStream(stm, (PBYTE)&numOffsets, 2);
	vector<WORD> modulesStarts(numModules);
	ReadStream(stm, (PBYTE)&modulesStarts[0], numModules * 2);
	vector<WORD> modulesLengths(numModules);
	ReadStream(stm, (PBYTE)&modulesLengths[0], numModules * 2);
	vector<DWORD> offsets(numOffsets);
	ReadStream(stm, (PBYTE)&offsets[0], numOffsets * 4);
	DWORD sourcesStart = stm.pos;
	for (int m = 0; m < numModules; m++)
	{
		cout << "Module #" << m << " sources" << endl;
		for (int i = modulesStarts[m]; i < modulesStarts[m] + modulesLengths[m]; i++)
		{
			stm.pos = sourcesStart + offsets[i];
			string sourcePath;
			ReadZString(stm, sourcePath);
			wcout << " #" << i << "  " << utf8towcs(sourcePath.c_str()) << endl;
		}
	}

	WORD stmno;
	stm.pos = start + modsHdr.SourcesLength;
	DumpStreamToFile(stm, stm.pos, modsHdr.LengthSomeData3, "somedata3.bin");
	stm.pos += modsHdr.LengthSomeData3;
	DumpStreamToFile(stm, stm.pos, modsHdr.LengthSomeData4, "somedata4.bin");
	stm.pos += 0xA;
	ReadStream(stm, (PBYTE)&stmno, 2);
	cout << "Sections stream 2: " << stmno << endl;

	stm.pos += 0x6;
	ReadStream(stm, (PBYTE)&stmno, 2);
	cout << "Unknown stream: " << stmno << endl;

	CloseHandle(PdbFile);
	return 0;
}
