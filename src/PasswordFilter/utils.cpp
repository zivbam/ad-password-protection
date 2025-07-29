#include "stdafx.h"
#include "utils.h"
#include <vector>
#include "SecureArrayT.h"
#include <atlalloc.h>
#include <secext.h>
#include <lm.h>

std::vector<std::wstring> SplitString(const std::wstring &text, const wchar_t sep)
{
	std::vector<std::wstring> tokens;
	std::size_t start = 0, end = 0;
	while ((end = text.find(sep, start)) != std::wstring::npos) {
		if (end != start) {
			tokens.push_back(text.substr(start, end - start));
		}
		start = end + 1;
	}
	if (end != start) {
		tokens.push_back(text.substr(start));
	}

	return tokens;
}

SecureArrayT<WCHAR> StringToWcharArray(const LPCWSTR str)
{
	const int charCount = (int)wcslen(str);
	const int len = charCount + 1;

	SecureArrayT<WCHAR> ar(len);

	wcsncpy_s(ar.get(), len, str, charCount);

	return ar;
}

SecureArrayT<WCHAR> UnicodeStringToWcharArray(const UNICODE_STRING& str)
{
	const int charCount = str.Length / sizeof(wchar_t);
	const int len = charCount + 1;

	SecureArrayT<WCHAR> ar (len);

	wcsncpy_s(ar.get(), len, str.Buffer, charCount);

	return ar;
}

bool DirectoryExists(const std::wstring& dirName)
{
	const DWORD attributes = GetFileAttributes(dirName.c_str());

	if (attributes == INVALID_FILE_ATTRIBUTES)
	{
		return false;
	}

        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::wstring GetUserDistinguishedName(const std::wstring& accountName)
{
        std::wstring samName = accountName;

        if (accountName.find(L'\\') == std::wstring::npos)
        {
                WCHAR domain[MAX_PATH] = {0};
                DWORD size = ARRAYSIZE(domain);
                if (GetComputerNameEx(ComputerNameDnsDomain, domain, &size))
                {
                        samName = std::wstring(domain) + L"\\" + accountName;
                }
        }

        DWORD requiredSize = 0;
        TranslateNameW(samName.c_str(), NameSamCompatible, NameFullyQualifiedDN, NULL, &requiredSize);
        if (requiredSize == 0)
        {
                return L"";
        }

        std::unique_ptr<WCHAR[]> buffer = std::make_unique<WCHAR[]>(requiredSize);
        if (!TranslateNameW(samName.c_str(), NameSamCompatible, NameFullyQualifiedDN, buffer.get(), &requiredSize))
        {
                return L"";
        }

        return std::wstring(buffer.get());
}

bool IsDnUnderOu(const std::wstring& dn, const std::wstring& ouDn)
{
        if (dn.length() < ouDn.length())
        {
                return false;
        }

        size_t pos = dn.length() - ouDn.length();
        if (_wcsicmp(dn.c_str() + pos, ouDn.c_str()) == 0)
        {
                return true;
        }

        return false;
}

bool IsUserMemberOfGroup(const std::wstring& accountName, const std::wstring& groupName)
{
        DWORD entriesRead = 0;
        DWORD totalEntries = 0;
        LPBYTE buffer = NULL;

        if (NetUserGetLocalGroups(NULL, accountName.c_str(), 0, LG_INCLUDE_INDIRECT, &buffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries) == NERR_Success)
        {
                GROUP_USERS_INFO_0* info = reinterpret_cast<GROUP_USERS_INFO_0*>(buffer);
                for (DWORD i = 0; i < entriesRead; ++i)
                {
                        if (_wcsicmp(info[i].grui0_name, groupName.c_str()) == 0)
                        {
                                NetApiBufferFree(buffer);
                                return true;
                        }
                }
                NetApiBufferFree(buffer);
        }

        entriesRead = 0;
        totalEntries = 0;
        buffer = NULL;

        if (NetUserGetGroups(NULL, accountName.c_str(), 0, &buffer, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries) == NERR_Success)
        {
                GROUP_USERS_INFO_0* info = reinterpret_cast<GROUP_USERS_INFO_0*>(buffer);
                for (DWORD i = 0; i < entriesRead; ++i)
                {
                        if (_wcsicmp(info[i].grui0_name, groupName.c_str()) == 0)
                        {
                                NetApiBufferFree(buffer);
                                return true;
                        }
                }
                NetApiBufferFree(buffer);
        }

        return false;
}
