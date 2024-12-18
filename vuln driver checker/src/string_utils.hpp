#pragma once

#include <string>
#include <windows.h>

// String conversion functions declaration
std::wstring string_to_wstring(const std::string& str);
std::string wstring_to_string(const std::wstring& wstr); 