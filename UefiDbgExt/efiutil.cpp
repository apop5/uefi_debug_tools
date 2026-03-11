/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    efiutil.cpp

Abstract:

    This file contains generic utility function for parsing EFI structures.

--*/

#include "uefiext.h"
#include <winnt.h>

#pragma pack(push, 1)
typedef struct {
  UINT16                  Signature;
  UINT16                  Machine;
  UINT8                   NumberOfSections;
  UINT8                   Subsystem;
  UINT16                  StrippedSize;
  UINT32                  AddressOfEntryPoint;
  UINT32                  BaseOfCode;
  UINT64                  ImageBase;
  IMAGE_DATA_DIRECTORY    DataDirectory[2];
} EFI_TE_IMAGE_HEADER;

typedef union {
  struct {
    UINT8    Header;
    UINT8    File;
  } Checksum;
  UINT16    Checksum16;
} EFI_FFS_INTEGRITY_CHECK;

typedef struct {
  GUID                       Name;
  EFI_FFS_INTEGRITY_CHECK    IntegrityCheck;
  UINT8                      Type;
  UINT8                      Attributes;
  UINT8                      Size[3];
  UINT8                      State;
} EFI_FFS_FILE_HEADER;

typedef struct {
  EFI_FFS_FILE_HEADER    Header;
  UINT32                 ExtendedSize;
} EFI_FFS_FILE_HEADER2;

typedef struct {
  UINT8     ZeroVector[16];
  GUID      FileSystemGuid;
  UINT64    FvLength;
  UINT32    Signature;
  UINT32    Attributes;
  UINT16    HeaderLength;
  UINT16    Checksum;
  UINT16    ExtHeaderOffset;
  UINT8     Reserved[1];
  UINT8     Revision;
} EFI_FIRMWARE_VOLUME_HEADER;

typedef struct {
  GUID       FileGuid;
  ULONG64    FileHeaderAddress;
  UINT32     FileSize;
  UINT8      Type;
  UINT8      Attributes;
  UINT8      State;
  UINT8      HeaderChecksum;
  UINT8      FileChecksum;
  BOOLEAN    UsesExtendedSize;
} FFS_FILE_INFO;
#pragma pack(pop)

#define EFI_TE_IMAGE_HEADER_SIGNATURE  0x5A56     // 'VZ'
#define EFI_FVH_SIGNATURE              0x4856465F // '_FVH'

static
UINT32
GetFfsFileSize (
  IN UINT8  Size[3]
  )
{
  return (UINT32)(Size[0] | (Size[1] << 8) | (Size[2] << 16));
}

static
BOOLEAN
IsGuidAllByte (
  IN const GUID  *Value,
  IN UINT8       Byte
  )
{
  const UINT8  *GuidBytes;
  ULONG        i;

  GuidBytes = (const UINT8 *)Value;
  for (i = 0; i < sizeof (GUID); i++) {
    if (GuidBytes[i] != Byte) {
      return FALSE;
    }
  }

  return TRUE;
}

static
BOOLEAN
TryGetContainingFfsFileInfo (
  IN  ULONG64        ImageAddress,
  OUT FFS_FILE_INFO  *FileInfo
  )
{
  ULONG64                     MinAddress;
  ULONG64                     FvBase;
  ULONG64                     Address;
  ULONG                       BytesRead;
  EFI_FIRMWARE_VOLUME_HEADER  FvHeader;

  if (FileInfo == NULL) {
    return FALSE;
  }

  // Search backward for a firmware volume header signature (_FVH), then parse FFS files.
  if (ImageAddress > 0x1000000) {
    MinAddress = ImageAddress - 0x1000000;
  } else {
    MinAddress = 0;
  }

  FvBase  = 0;
  Address = ImageAddress & ~(ULONG64)0x7;
  for ( ; Address >= MinAddress; ) {
    BytesRead = 0;
    if (ReadMemory (Address, &FvHeader, sizeof (FvHeader), &BytesRead) && (BytesRead == sizeof (FvHeader))) {
      if ((FvHeader.Signature == EFI_FVH_SIGNATURE) &&
          (FvHeader.HeaderLength >= sizeof (EFI_FIRMWARE_VOLUME_HEADER)) &&
          (FvHeader.FvLength >= FvHeader.HeaderLength) &&
          (Address + FvHeader.FvLength > ImageAddress))
      {
        FvBase = Address;
        break;
      }
    }

    if (Address == MinAddress) {
      break;
    }

    Address -= 0x8;
  }

  if (FvBase == 0) {
    return FALSE;
  }

  {
    ULONG64  FileAddress;
    ULONG64  FvEnd;

    FvEnd       = FvBase + FvHeader.FvLength;
    FileAddress = (FvBase + FvHeader.HeaderLength + 7) & ~(ULONG64)0x7;

    while ((FileAddress + sizeof (EFI_FFS_FILE_HEADER)) <= FvEnd) {
      EFI_FFS_FILE_HEADER  Header;
      UINT32               FileSize;
      BOOLEAN              IsExtendedSize;
      ULONG64              EndAddress;

      BytesRead = 0;
      if (!ReadMemory (FileAddress, &Header, sizeof (Header), &BytesRead) || (BytesRead != sizeof (Header))) {
        break;
      }

      if ((Header.Type == 0xFF) && IsGuidAllByte (&Header.Name, 0xFF)) {
        // Unused space in FV.
        break;
      }

      FileSize       = GetFfsFileSize (Header.Size);
      IsExtendedSize = FALSE;
      if (FileSize == 0x00FFFFFF) {
        EFI_FFS_FILE_HEADER2  Header2;

        BytesRead = 0;
        if (ReadMemory (FileAddress, &Header2, sizeof (Header2), &BytesRead) && (BytesRead == sizeof (Header2))) {
          FileSize       = Header2.ExtendedSize;
          IsExtendedSize = TRUE;
        }
      }

      if ((FileSize < sizeof (EFI_FFS_FILE_HEADER)) || (FileSize == 0xFFFFFFFF)) {
        break;
      }

      EndAddress = FileAddress + (ULONG64)FileSize;
      if (EndAddress > FvEnd) {
        break;
      }

      if ((FileAddress <= ImageAddress) && (ImageAddress < EndAddress) &&
          (Header.Type != 0xFF) && !IsGuidAllByte (&Header.Name, 0x00) && !IsGuidAllByte (&Header.Name, 0xFF))
      {
        FileInfo->FileGuid          = Header.Name;
        FileInfo->FileHeaderAddress = FileAddress;
        FileInfo->FileSize          = FileSize;
        FileInfo->Type              = Header.Type;
        FileInfo->Attributes        = Header.Attributes;
        FileInfo->State             = Header.State;
        FileInfo->HeaderChecksum    = Header.IntegrityCheck.Checksum.Header;
        FileInfo->FileChecksum      = Header.IntegrityCheck.Checksum.File;
        FileInfo->UsesExtendedSize  = IsExtendedSize;
        return TRUE;
      }

      FileAddress = (EndAddress + 7) & ~(ULONG64)0x7;
    }
  }

  // Fallback heuristic for targets with partially mapped firmware memory.
  Address = ImageAddress & ~(ULONG64)0x7;
  if (ImageAddress > 0x20000) {
    MinAddress = ImageAddress - 0x20000;
  } else {
    MinAddress = 0;
  }

  for ( ; Address >= MinAddress; ) {
    UINT32               FileSize;
    BOOLEAN              IsExtendedSize;
    EFI_FFS_FILE_HEADER  Header;

    BytesRead = 0;
    if (!ReadMemory (Address, &Header, sizeof (Header), &BytesRead) || (BytesRead != sizeof (Header))) {
      if (Address == MinAddress) {
        break;
      }

      Address -= 0x8;
      continue;
    }

    if ((Header.Type != 0xFF) && !IsGuidAllByte (&Header.Name, 0x00) && !IsGuidAllByte (&Header.Name, 0xFF)) {
      FileSize       = GetFfsFileSize (Header.Size);
      IsExtendedSize = FALSE;
      if (FileSize == 0x00FFFFFF) {
        EFI_FFS_FILE_HEADER2  Header2;

        BytesRead = 0;
        if (ReadMemory (Address, &Header2, sizeof (Header2), &BytesRead) && (BytesRead == sizeof (Header2))) {
          FileSize       = Header2.ExtendedSize;
          IsExtendedSize = TRUE;
        }
      }

      if ((FileSize >= sizeof (EFI_FFS_FILE_HEADER)) && (FileSize != 0xFFFFFFFF)) {
        ULONG64  EndAddress;

        EndAddress = Address + (ULONG64)FileSize;
        if ((Address <= ImageAddress) && (ImageAddress < EndAddress)) {
          FileInfo->FileGuid          = Header.Name;
          FileInfo->FileHeaderAddress = Address;
          FileInfo->FileSize          = FileSize;
          FileInfo->Type              = Header.Type;
          FileInfo->Attributes        = Header.Attributes;
          FileInfo->State             = Header.State;
          FileInfo->HeaderChecksum    = Header.IntegrityCheck.Checksum.Header;
          FileInfo->FileChecksum      = Header.IntegrityCheck.Checksum.File;
          FileInfo->UsesExtendedSize  = IsExtendedSize;
          return TRUE;
        }
      }
    }

    if (Address == MinAddress) {
      break;
    }

    Address -= 0x8;
  }

  return FALSE;
}

static
PCSTR
FfsFileTypeToString (
  IN UINT8  Type
  )
{
  switch (Type) {
    case 0x01:
      return "RAW";
    case 0x02:
      return "FREEFORM";
    case 0x03:
      return "SECURITY_CORE";
    case 0x04:
      return "PEI_CORE";
    case 0x05:
      return "DXE_CORE";
    case 0x06:
      return "PEIM";
    case 0x07:
      return "DRIVER";
    case 0x08:
      return "COMBINED_PEIM_DRIVER";
    case 0x09:
      return "APPLICATION";
    case 0x0A:
      return "MM";
    case 0x0B:
      return "FIRMWARE_VOLUME_IMAGE";
    case 0x0C:
      return "COMBINED_MM_DXE";
    case 0x0D:
      return "MM_CORE";
    case 0xF0:
      return "FFS_PAD";
    default:
      return "UNKNOWN";
  }
}

static
ULONG64
GetCurrentIpOrPc (
  VOID
  )
{
  ULONG64  Address;

  Address = 0;
  if (g_TargetMachine == IMAGE_FILE_MACHINE_AMD64) {
    Address = GetRegisterValue ("rip");
  } else if (g_TargetMachine == IMAGE_FILE_MACHINE_ARM64) {
    Address = GetRegisterValue ("pc");
  }

  if ((Address == 0) || (Address == (ULONG64)-1)) {
    Address = GetExpression ("@$ip");
  }

  return Address;
}

static
BOOLEAN
IsValidTeHeader (
  IN ULONG64  Address
  )
{
  EFI_TE_IMAGE_HEADER  Header;
  ULONG                BytesRead;

  BytesRead = 0;
  if (!ReadMemory (Address, &Header, sizeof (Header), &BytesRead) || (BytesRead != sizeof (Header))) {
    return FALSE;
  }

  if (Header.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE) {
    return FALSE;
  }

  if ((Header.NumberOfSections == 0) || (Header.StrippedSize < sizeof (EFI_TE_IMAGE_HEADER))) {
    return FALSE;
  }

  if ((Header.Machine != IMAGE_FILE_MACHINE_I386) &&
      (Header.Machine != IMAGE_FILE_MACHINE_AMD64) &&
      (Header.Machine != IMAGE_FILE_MACHINE_ARM64))
  {
    return FALSE;
  }

  if ((Header.Subsystem < IMAGE_SUBSYSTEM_EFI_APPLICATION) ||
      (Header.Subsystem > IMAGE_SUBSYSTEM_EFI_ROM))
  {
    return FALSE;
  }

  return TRUE;
}

static
BOOLEAN
IsValidPeImage (
  IN ULONG64  Address
  )
{
  IMAGE_DOS_HEADER   DosHeader;
  ULONG              BytesRead;
  ULONG64            NtHeaderAddress;
  ULONG              NtSignature;
  IMAGE_FILE_HEADER  FileHeader;
  UINT16             OptionalMagic;

  BytesRead = 0;
  if (!ReadMemory (Address, &DosHeader, sizeof (DosHeader), &BytesRead) || (BytesRead != sizeof (DosHeader))) {
    return FALSE;
  }

  if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  // PE header should be close to image start for firmware images.
  if ((DosHeader.e_lfanew < sizeof (IMAGE_DOS_HEADER)) || (DosHeader.e_lfanew > 0x1000)) {
    return FALSE;
  }

  NtHeaderAddress = Address + (ULONG64)DosHeader.e_lfanew;
  NtSignature     = 0;
  if (!ReadMemory (NtHeaderAddress, &NtSignature, sizeof (NtSignature), &BytesRead) || (BytesRead != sizeof (NtSignature))) {
    return FALSE;
  }

  if (NtSignature != IMAGE_NT_SIGNATURE) {
    return FALSE;
  }

  if (!ReadMemory (NtHeaderAddress + sizeof (NtSignature), &FileHeader, sizeof (FileHeader), &BytesRead) || (BytesRead != sizeof (FileHeader))) {
    return FALSE;
  }

  if ((FileHeader.NumberOfSections == 0) || (FileHeader.NumberOfSections > 96)) {
    return FALSE;
  }

  if (FileHeader.SizeOfOptionalHeader < sizeof (UINT16)) {
    return FALSE;
  }

  OptionalMagic = 0;
  if (!ReadMemory (NtHeaderAddress + sizeof (NtSignature) + sizeof (FileHeader), &OptionalMagic, sizeof (OptionalMagic), &BytesRead) || (BytesRead != sizeof (OptionalMagic))) {
    return FALSE;
  }

  if ((OptionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
    return FALSE;
  }

  return TRUE;
}

static
BOOLEAN
TryGetPePdbPath (
  IN  ULONG64  Address,
  OUT PCHAR    PdbPath,
  IN  ULONG    PdbPathSize
  )
{
  IMAGE_DOS_HEADER       DosHeader;
  ULONG64                NtHeadersAddr;
  ULONG                  BytesRead;
  ULONG                  NtSignature;
  IMAGE_FILE_HEADER      FileHeader;
  UINT16                 OptionalMagic;
  UINT32                 DebugDirRva;
  UINT32                 DebugDirSize;
  UINT32                 ImageSize;
  ULONG                  NumEntries;
  IMAGE_DEBUG_DIRECTORY  DebugEntries[32];
  ULONG                  i;

  if ((PdbPath == NULL) || (PdbPathSize < 2)) {
    return FALSE;
  }

  PdbPath[0] = '\0';

  BytesRead = 0;
  if (!ReadMemory (Address, &DosHeader, sizeof (DosHeader), &BytesRead) || (BytesRead != sizeof (DosHeader))) {
    return FALSE;
  }

  if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  NtHeadersAddr = Address + (ULONG64)DosHeader.e_lfanew;
  NtSignature   = 0;
  if (!ReadMemory (NtHeadersAddr, &NtSignature, sizeof (NtSignature), &BytesRead) || (BytesRead != sizeof (NtSignature))) {
    return FALSE;
  }

  if (NtSignature != IMAGE_NT_SIGNATURE) {
    return FALSE;
  }

  if (!ReadMemory (NtHeadersAddr + sizeof (NtSignature), &FileHeader, sizeof (FileHeader), &BytesRead) || (BytesRead != sizeof (FileHeader))) {
    return FALSE;
  }

  OptionalMagic = 0;
  if (!ReadMemory (NtHeadersAddr + sizeof (NtSignature) + sizeof (FileHeader), &OptionalMagic, sizeof (OptionalMagic), &BytesRead) || (BytesRead != sizeof (OptionalMagic))) {
    return FALSE;
  }

  DebugDirRva  = 0;
  DebugDirSize = 0;
  ImageSize    = 0;
  if (OptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    IMAGE_OPTIONAL_HEADER64  Optional64;

    if (!ReadMemory (NtHeadersAddr + sizeof (NtSignature) + sizeof (FileHeader), &Optional64, sizeof (Optional64), &BytesRead) || (BytesRead != sizeof (Optional64))) {
      return FALSE;
    }

    DebugDirRva  = Optional64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    DebugDirSize = Optional64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    ImageSize    = Optional64.SizeOfImage;
  } else if (OptionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    IMAGE_OPTIONAL_HEADER32  Optional32;

    if (!ReadMemory (NtHeadersAddr + sizeof (NtSignature) + sizeof (FileHeader), &Optional32, sizeof (Optional32), &BytesRead) || (BytesRead != sizeof (Optional32))) {
      return FALSE;
    }

    DebugDirRva  = Optional32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    DebugDirSize = Optional32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
    ImageSize    = Optional32.SizeOfImage;
  } else {
    return FALSE;
  }

  if ((DebugDirRva == 0) || (DebugDirSize < sizeof (IMAGE_DEBUG_DIRECTORY))) {
    return FALSE;
  }

  NumEntries = DebugDirSize / sizeof (IMAGE_DEBUG_DIRECTORY);
  if (NumEntries > ARRAYSIZE (DebugEntries)) {
    NumEntries = ARRAYSIZE (DebugEntries);
  }

  if (!ReadMemory (Address + DebugDirRva, DebugEntries, NumEntries * sizeof (IMAGE_DEBUG_DIRECTORY), &BytesRead) || (BytesRead != (NumEntries * sizeof (IMAGE_DEBUG_DIRECTORY)))) {
    return FALSE;
  }

  for (i = 0; i < NumEntries; i++) {
    IMAGE_DEBUG_DIRECTORY  *Entry;
    ULONG64                CvAddress;
    CHAR                   Signature[4];
    ULONG                  CvHeaderSize;
    ULONG64                PdbPathAddress;
    ULONG                  SizeToRead;

    Entry = &DebugEntries[i];
    if (Entry->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
      continue;
    }

    CvAddress = 0;
    if ((Entry->AddressOfRawData != 0) && (ImageSize != 0) &&
        ((ULONG64)Entry->AddressOfRawData >= Address) &&
        ((ULONG64)Entry->AddressOfRawData < (Address + (ULONG64)ImageSize)))
    {
      CvAddress = (ULONG64)Entry->AddressOfRawData;
    } else if (Entry->AddressOfRawData != 0) {
      CvAddress = Address + (ULONG64)Entry->AddressOfRawData;
    } else if (Entry->PointerToRawData != 0) {
      CvAddress = Address + (ULONG64)Entry->PointerToRawData;
    } else {
      continue;
    }

    if (!ReadMemory (CvAddress, Signature, sizeof (Signature), &BytesRead) || (BytesRead != sizeof (Signature))) {
      continue;
    }

    if (memcmp (Signature, "RSDS", 4) == 0) {
      CvHeaderSize = 24;
    } else if (memcmp (Signature, "NB10", 4) == 0) {
      CvHeaderSize = 16;
    } else {
      continue;
    }

    PdbPathAddress = CvAddress + CvHeaderSize;
    SizeToRead     = PdbPathSize - 1;
    if ((Entry->SizeOfData > CvHeaderSize) && (Entry->SizeOfData - CvHeaderSize < SizeToRead)) {
      SizeToRead = Entry->SizeOfData - CvHeaderSize;
    }

    if ((SizeToRead == 0) || !ReadMemory (PdbPathAddress, PdbPath, SizeToRead, &BytesRead) || (BytesRead == 0)) {
      continue;
    }

    PdbPath[(BytesRead < (PdbPathSize - 1)) ? BytesRead : (PdbPathSize - 1)] = '\0';
    if (PdbPath[0] != '\0') {
      return TRUE;
    }
  }

  return FALSE;
}

UINT64
GetNextListEntry (
  IN ULONG64  Head,
  IN LPCSTR   Type,
  IN LPCSTR   Field,
  IN UINT64   Previous
  )
{
  ULONG    LinkOffset;
  ULONG64  LinkAddress;

  if (Head == 0) {
    dprintf ("Invalid list head!\n");
    return 0;
  }

  GetFieldOffset (Type, Field, &LinkOffset);

  if (Previous == 0) {
    GetFieldValue (Head, "_LIST_ENTRY", "ForwardLink", LinkAddress);
  } else {
    GetFieldValue (Previous + LinkOffset, "_LIST_ENTRY", "ForwardLink", LinkAddress);
  }

  if (LinkAddress == 0) {
    dprintf ("Invalid list link!\n");
    return 0;
  }

  if (LinkAddress == Head) {
    return 0;
  }

  return (LinkAddress - LinkOffset);
}

PCSTR
ErrorLevelToString (
  UINT32  ErrorLevel
  )
{
  switch (ErrorLevel) {
    case 0x00000001:
      return "INIT";
    case 0x00000002:
      return "WARN";
    case 0x00000004:
      return "LOAD";
    case 0x00000008:
      return "FS";
    case 0x00000010:
      return "POOL";
    case 0x00000020:
      return "PAGE";
    case 0x00000040:
      return "INFO";
    case 0x00000080:
      return "DISPATCH";
    case 0x00000100:
      return "VARIABLE";
    case 0x00000200:
      return "SMI";
    case 0x00000400:
      return "BM";
    case 0x00001000:
      return "BLKIO";
    case 0x00004000:
      return "NET";
    case 0x00010000:
      return "UNDI";
    case 0x00020000:
      return "LDFILE";
    case 0x00080000:
      return "EVENT";
    case 0x00100000:
      return "GCD";
    case 0x00200000:
      return "CACHE";
    case 0x00400000:
      return "VERBOSE";
    case 0x00800000:
      return "MANAGEABILITY";
    case 0x80000000:
      return "ERROR";
    default:
      return "UNK";
  }
}

PCHAR
GuidToString (
  GUID  *Guid
  )
{
  static CHAR  GuidBuffer[40];

  sprintf_s (
    GuidBuffer,
    sizeof (GuidBuffer),
    "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
    Guid->Data1,
    Guid->Data2,
    Guid->Data3,
    Guid->Data4[0],
    Guid->Data4[1],
    Guid->Data4[2],
    Guid->Data4[3],
    Guid->Data4[4],
    Guid->Data4[5],
    Guid->Data4[6],
    Guid->Data4[7]
    );

  return GuidBuffer;
}

ULONG
TokenizeArgs (
  PCSTR  args,
  PSTR   **Tokens
  )
{
  static CHAR  Strings[128];
  static CHAR  *TokenList[32];
  ULONG        Count;
  CHAR         *Curr;
  BOOLEAN      InToken;

  if (strlen (args) >= sizeof (Strings)) {
    dprintf ("Arguments too long for tokenizer!");
    return 0;
  }

  strcpy_s (Strings, sizeof (Strings), args);

  Count   = 0;
  Curr    = &Strings[0];
  InToken = FALSE;
  while (*Curr != '\0') {
    if (*Curr == ' ') {
      InToken = FALSE;
      *Curr   = '\0';
    } else if (!InToken) {
      if (Count >= sizeof (TokenList)) {
        dprintf ("Too many tokens!");
        return 0;
      }

      TokenList[Count] = Curr;
      InToken          = TRUE;
      Count++;
    }

    Curr++;
  }

  if (Tokens != NULL) {
    *Tokens = TokenList;
  }

  return Count;
}

HRESULT CALLBACK
linkedlist (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  PSTR     *Tokens;
  ULONG    TokenCount;
  ULONG64  HeadAddr;
  ULONG64  Entry;
  CHAR     Command[256];

  INIT_API ();

  TokenCount = TokenizeArgs (args, &Tokens);
  if (TokenCount != 3) {
    dprintf ("Usage: !linkedlist <List Head> <Type> <Link Field>");
    return ERROR_INVALID_PARAMETER;
  }

  if (GetExpressionEx (Tokens[0], &HeadAddr, NULL) == FALSE) {
    dprintf ("Invalid list head!");
    return ERROR_INVALID_PARAMETER;
  }

  Entry = 0;
  while ((Entry = GetNextListEntry (HeadAddr, Tokens[1], Tokens[2], Entry)) != 0) {
    sprintf_s (&Command[0], sizeof (Command), "dt (%s)%I64x", Tokens[1], Entry);
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_ALL_CLIENTS,
                    &Command[0],
                    DEBUG_EXECUTE_DEFAULT
                    );
  }

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
efierror (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG64        Error;
  ULONG64        ErrorOffset;
  CONST ULONG64  ErrorBit = 0x8000000000000000ULL;
  PCSTR          String;
  CONST PCSTR    Codes[] = {
    "EFI_SUCCESS",                // 0
    "EFI_WARN_UNKNOWN_GLYPH",     // 1
    "EFI_WARN_DELETE_FAILURE",    // 2
    "EFI_WARN_WRITE_FAILURE",     // 3
    "EFI_WARN_BUFFER_TOO_SMALL",  // 4
    "EFI_WARN_STALE_DATA",        // 5
    "EFI_WARN_FILE_SYSTEM"        // 6
  };

  CONST PCSTR  ErrorCodes[] = {
    "UNKNOWN",                    // 0
    "EFI_LOAD_ERROR",             // 1
    "EFI_INVALID_PARAMETER",      // 2
    "EFI_UNSUPPORTED",            // 3
    "EFI_BAD_BUFFER_SIZE",        // 4
    "EFI_BUFFER_TOO_SMALL",       // 5
    "EFI_NOT_READY",              // 6
    "EFI_DEVICE_ERROR",           // 7
    "EFI_WRITE_PROTECTED",        // 8
    "EFI_OUT_OF_RESOURCES",       // 9
    "EFI_VOLUME_CORRUPTED",       // 10
    "EFI_VOLUME_FULL",            // 11
    "EFI_NO_MEDIA",               // 12
    "EFI_MEDIA_CHANGED",          // 13
    "EFI_NOT_FOUND",              // 14
    "EFI_ACCESS_DENIED",          // 15
    "EFI_NO_RESPONSE",            // 16
    "EFI_NO_MAPPING",             // 17
    "EFI_TIMEOUT",                // 18
    "EFI_NOT_STARTED",            // 19
    "EFI_ALREADY_STARTED",        // 20
    "EFI_ABORTED",                // 21
    "EFI_ICMP_ERROR",             // 22
    "EFI_TFTP_ERROR",             // 23
    "EFI_PROTOCOL_ERROR",         // 24
    "EFI_INCOMPATIBLE_VERSION"    // 25
    "EFI_SECURITY_VIOLATION",     // 26
    "EFI_CRC_ERROR",              // 27
    "EFI_END_OF_MEDIA",           // 28
    "UNKNOWN",                    // 29
    "UNKNOWN",                    // 30
    "EFI_END_OF_FILE",            // 31
    "EFI_INVALID_LANGUAGE",       // 32
    "EFI_COMPROMISED_DATA",       // 33
    "UNKNOWN",                    // 34
    "EFI_HTTP_ERROR"              // 35
  };

  INIT_API ();

  if (GetExpressionEx (args, &Error, NULL) == FALSE) {
    dprintf ("Must provide error code or variable!");
    return ERROR_INVALID_PARAMETER;
  }

  String = "UNKNOWN";
  if ((Error & ErrorBit) != 0) {
    ErrorOffset = Error & ~ErrorBit;
    if (ErrorOffset < ARRAYSIZE (ErrorCodes)) {
      String = ErrorCodes[ErrorOffset];
    }
  } else if (Error < ARRAYSIZE (Codes)) {
    String = Codes[Error];
  }

  dprintf ("0x%I64x = %s\n", Error, String);

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
find_image (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG64        StartAddress;
  ULONG64        Address;
  ULONG64        MinAddress;
  ULONG64        MaxSize;
  CONST ULONG64  ScanStride = 0x4;
  ULONG32        Check;
  ULONG          BytesRead;
  CONST UINT16   PeMagic = IMAGE_DOS_SIGNATURE;           // MZ
  CONST UINT16   TeMagic = EFI_TE_IMAGE_HEADER_SIGNATURE; // VZ
  CHAR           PdbPath[1024];
  FFS_FILE_INFO  FileInfo;
  HRESULT        hr = ERROR_NOT_FOUND;

  INIT_API ();

  if (strlen (args) == 0) {
    Address = GetCurrentIpOrPc ();
  } else {
    Address = GetExpression (args);
  }

  if ((Address == 0) || (Address == (ULONG64)-1)) {
    dprintf ("Invalid address!\n");
    dprintf ("Usage: !uefiext.find_image [Address]\n");
    hr = ERROR_INVALID_PARAMETER;
    goto Cleanup;
  }

  StartAddress = Address;
  Address     &= ~(ScanStride - 1);
  MaxSize      = 0x100000; // 1 MB
  if (Address > MaxSize) {
    MinAddress = (Address - MaxSize) & ~(ScanStride - 1);
  } else {
    MinAddress = 0;
  }

  for ( ; Address >= MinAddress; ) {
    Check = 0;
    if (!ReadMemory (Address, &Check, sizeof (Check), &BytesRead) || (BytesRead != sizeof (Check))) {
      break;
    }

    if ((Check & 0xFFFF) == PeMagic) {
      if (IsValidPeImage (Address)) {
        dprintf ("Found PE/COFF image at %llx\n", Address);
        if (TryGetPePdbPath (Address, PdbPath, sizeof (PdbPath))) {
          dprintf ("  PDB: %s\n", PdbPath);
        } else {
          dprintf ("  PDB: not found\n");
          dprintf ("  try .reload /f <Module-Name>=%llx\n", Address);
          if (TryGetContainingFfsFileInfo (Address, &FileInfo)) {
            dprintf ("  FFS FILE_GUID at %llx: %s\n", FileInfo.FileHeaderAddress, GuidToString (&FileInfo.FileGuid));
            dprintf ("  FFS type: 0x%02x (%s)\n", FileInfo.Type, FfsFileTypeToString (FileInfo.Type));
            dprintf ("  FFS size: 0x%x (%u)%s\n", FileInfo.FileSize, FileInfo.FileSize, FileInfo.UsesExtendedSize ? " [extended]" : "");
            dprintf ("  FFS attributes: 0x%02x\n", FileInfo.Attributes);
            dprintf ("  FFS state: 0x%02x\n", FileInfo.State);
            dprintf ("  FFS checksum: header=0x%02x file=0x%02x\n", FileInfo.HeaderChecksum, FileInfo.FileChecksum);
          } else {
            dprintf ("  FFS FILE_GUID: not found\n");
          }
        }

        hr = S_OK;
        goto Cleanup;
      }
    }

    if ((Check & 0xFFFF) == TeMagic) {
      if (IsValidTeHeader (Address)) {
        dprintf ("Found TE image at %llx\n", Address);
        hr = S_OK;
        goto Cleanup;
      }
    }

    if (Address == MinAddress) {
      break;
    }

    Address -= ScanStride;
  }

  dprintf ("No PE/COFF or TE image found scanning backward from %llx\n", StartAddress);

Cleanup:
  EXIT_API ();
  return hr;
}
