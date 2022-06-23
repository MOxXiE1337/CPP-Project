--[[
    C++ RTTI信息分析库 用于硬取虚函数的库
    github: https://github.com/MOxXiE1337/CPP-Project
    版本：2022/6/9 1.0
    作者: MOxXiE1337 (QQ:938583253)
    适用: 所有支持ffi的Cheat
    注:此代码为硬特征
]]

local ffi = require "ffi"
local bit = require "bit"

local kernel32 = ffi.load("kernel32.dll");

local modname = ...

local M = {} 

_G[modname] = M 
complex = M

--all classes and function we need

ffi.cdef[[
    typedef void* HMODULE;
    typedef const char* LPCSTR;
    HMODULE GetModuleHandleA(LPCSTR lpModuleName);

    typedef long LONG;
    typedef unsigned char BYTE;
    typedef unsigned short WORD;
    typedef unsigned long DWORD;

    typedef struct _IMAGE_DOS_HEADER {     
    WORD   e_magic;                    
    WORD   e_cblp;                      
    WORD   e_cp;                       
    WORD   e_crlc;                      
    WORD   e_cparhdr;                   
    WORD   e_minalloc;                  
    WORD   e_maxalloc;                  
    WORD   e_ss;                        
    WORD   e_sp;                        
    WORD   e_csum;                      
    WORD   e_ip;                       
    WORD   e_cs;                        
    WORD   e_lfarlc;                    
    WORD   e_ovno;                      
    WORD   e_res[4];                    
    WORD   e_oemid;                    
    WORD   e_oeminfo;                  
    WORD   e_res2[10];                  
    LONG   e_lfanew;                    
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_FILE_HEADER {
        WORD    Machine;
        WORD    NumberOfSections;
        DWORD   TimeDateStamp;
        DWORD   PointerToSymbolTable;
        DWORD   NumberOfSymbols;
        WORD    SizeOfOptionalHeader;
        WORD    Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_SECTION_HEADER {
        BYTE    Name[8];
        DWORD   VirtualSize;
        DWORD   VirtualAddress;
        DWORD   SizeOfRawData;
        DWORD   PointerToRawData;
        DWORD   PointerToRelocations;
        DWORD   PointerToLinenumbers;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
]]

function complex.SegmentInfo(moduleName)
    local result = {};
    result[".data"] = {};
    result[".rdata"] = {};
    result[".data"]["address"] = nil;
    result[".data"]["size"] = nil;
    result[".rdata"]["address"] = nil;
    result[".rdata"]["size"] = nil;

    local dosHeader = ffi.cast("PIMAGE_DOS_HEADER",kernel32.GetModuleHandleA(moduleName));
    local ntHeader = ffi.cast("void*",ffi.cast("uintptr_t",dosHeader) + dosHeader.e_lfanew);
    local fileHeader = ffi.cast("PIMAGE_FILE_HEADER",ffi.cast("uintptr_t",ntHeader) + 4);
    local section = ffi.cast("PIMAGE_SECTION_HEADER",ffi.cast("uintptr_t",ntHeader) + 248--[[sizeof(IMAGE_NT_HEADERS)]]) ;

    for u = 0,fileHeader.NumberOfSections do
        if(string.find(ffi.string(section[u].Name,8),".rdata") ~= nil) then
            result[".rdata"]["address"] = tonumber(ffi.cast("uintptr_t",dosHeader) + section[u].VirtualAddress);
            result[".rdata"]["size"] = tonumber(section[u].VirtualSize);
        else if (string.find(ffi.string(section[u].Name,8),".data") ~= nil) then
            result[".data"]["address"] = tonumber(ffi.cast("uintptr_t",dosHeader) + section[u].VirtualAddress);
            result[".data"]["size"] = tonumber(section[u].VirtualSize);
        end
        end
    end

    return result;
end

function complex.DataCompare(pdata,pattern,mask)
    for i = 1,#(mask) do
        if(mask[i] == 1 and tonumber(ffi.cast("unsigned char*",pdata)[0]) ~= pattern[i]) then
            return false;
        end
        pdata = pdata + 1;
    end
    return true;
end

function complex.FindPattern(startAddress,size,pattern,mask)
    for i = 0, size do
        if(complex.DataCompare(startAddress + i,pattern,mask)) then
            return tonumber(startAddress + i);
        end
    end
    return nil;
end

function complex.RTTIName(name)
    local rttiName = {};
    rttiName["class"] = ".?AV" .. name .. "@@";
    rttiName["struct"] = ".?AC" .. name .. "@@";
    return rttiName;
end

function complex.RTTINameToPattern(name)
    local result = {};
    result["pattern"] = {};
    result["mask"] = {};
    for i = 1,string.len(name) do
        local val = string.byte(name,i);
        table.insert(result["pattern"],val);
        table.insert(result["mask"],1);
    end
    return result;
end

function complex.GetVFTableByName(moduleName,name,offset)

    offset = offset or 0;

    --make offset pattern
    local ol8 = bit.band(offset,255);
    local oml8 = bit.rshift(bit.band(offset,65280), 8);
    local omh8 = bit.rshift(bit.band(offset,16711680), 16);
    local oh8 = bit.rshift(bit.band(offset,4278190080), 24);

    if(tonumber(kernel32.GetModuleHandleA(moduleName)) == 0) then
        print("CPP_RTTI: Can't get module base!");
        return nil;
    end

    local segInfo = complex.SegmentInfo(moduleName);

    if(segInfo[".data"]["address"] == nil or segInfo[".rdata"]["address"] == nil or segInfo[".data"]["size"] == nil or segInfo[".rdata"]["size"] == nil) then
        print("CPP_RTTI: Failed to parse segment!");
        return nil;
    end

    local rttiName = complex.RTTIName(name);
    local rttiNamePattern = complex.RTTINameToPattern(rttiName["class"]);
    local rttiNamePatternS = complex.RTTINameToPattern(rttiName["class"]);

    local rttiNameLocation = complex.FindPattern(segInfo[".data"]["address"],segInfo[".data"]["size"],rttiNamePattern["pattern"],rttiNamePattern["mask"]);

    if(rttiNameLocation == nil) then
        local rttiNameLocationS = complex.FindPattern(segInfo[".data"]["address"],segInfo[".data"]["size"],rttiNamePatternS["pattern"],rttiNamePatternS["mask"]);
        if(rttiNameLocationS == nil) then
            print("CPP_RTTI: Failed to search rtti partern: class name!");
        end
        return nil;
    end

    local pTypeDescriptor = rttiNameLocation - 8;

    --make pattern
    local l8 = bit.band(pTypeDescriptor,255);
    local ml8 = bit.rshift(bit.band(pTypeDescriptor,65280), 8);
    local mh8 = bit.rshift(bit.band(pTypeDescriptor,16711680), 16);
    local h8 = bit.rshift(bit.band(pTypeDescriptor,4278190080), 24);

    local RTTICompleteObjectLocatorPtrPattern = {0,0,0,0};

    table.insert(RTTICompleteObjectLocatorPtrPattern,ol8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,oml8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,omh8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,oh8);

    table.insert(RTTICompleteObjectLocatorPtrPattern,0);
    table.insert(RTTICompleteObjectLocatorPtrPattern,0);
    table.insert(RTTICompleteObjectLocatorPtrPattern,0);
    table.insert(RTTICompleteObjectLocatorPtrPattern,0);

    table.insert(RTTICompleteObjectLocatorPtrPattern,l8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,ml8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,mh8);
    table.insert(RTTICompleteObjectLocatorPtrPattern,h8);

    local RTTICompleteObjectLocatorPtr = complex.FindPattern(segInfo[".rdata"]["address"],segInfo[".rdata"]["size"],RTTICompleteObjectLocatorPtrPattern,{1,1,1,1,1,1,1,1,0,0,0,0,1,1,1,1});

    if(RTTICompleteObjectLocatorPtr == nil) then
        print("CPP_RTTI: Failed to search rtti partern: ObjectLoatorPtr");
        return nil;
    end
    
    --make pattern
    l8 = bit.band(RTTICompleteObjectLocatorPtr,255);
    ml8 = bit.rshift(bit.band(RTTICompleteObjectLocatorPtr,65280), 8);
    mh8 = bit.rshift(bit.band(RTTICompleteObjectLocatorPtr,16711680), 16);
    h8 = bit.rshift(bit.band(RTTICompleteObjectLocatorPtr,4278190080), 24);

    local vftablePtrPattern = {};
    table.insert(vftablePtrPattern,l8);
    table.insert(vftablePtrPattern,ml8);
    table.insert(vftablePtrPattern,mh8);
    table.insert(vftablePtrPattern,h8);

    local vftablePtr = complex.FindPattern(segInfo[".rdata"]["address"],segInfo[".rdata"]["size"],vftablePtrPattern,{1,1,1,1});

    if(vftablePtr == nil) then
        print("CPP_RTTI: Failed to search rtti partern: vftablePtr");
        return nil;
    end

    vftablePtr = vftablePtr + 4;

    return ffi.cast("uintptr_t*",vftablePtr);

end

return complex
