# ShellCodeGet
To Convert C Code to Shellcode

动态获取Kernel32基址，获取GetProcAddress地址
ShellCodeGet_x86.cpp -> 32位版本
ShellCodeGet_x64.cpp -> 64位版本

## 注意:
1. 避免使用常量字符串和全局变量，需使用字符串请用字节数组形式
2. 编译时禁用优化

使用函数时请使用`GetProcAddress` 和`LoadLibraryA` 来获取winapi函数地址 并定义函数指针
类似:
```cpp
typedef FARPROC (WINAPI* MYGetProcAddress) (HMODULE hModule, LPCSTR lpProcName);
```

详细请看我的博客[如何编写一个ShellCode](http://tupler.top/posts/%E5%85%8D%E6%9D%80%E4%BA%8C%E8%BF%9B%E5%88%B6%E6%89%8B%E5%8A%A8%E7%BC%96%E5%86%99%E8%8E%B7%E5%8F%96shellcode/)
