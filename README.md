# CPP-Project

CPP-Project是一个可以运行在任何Cheat的Lua库<br> 
没有使用到任何Cheat的任何API 只使用ffi与bit<br> 
(有些功能如特征码搜索会在lua中实现)<br> 
旨在帮助您更方便的使用ffi以及一些ffi进阶功能<br> 


## 子项目:

### CPP_RTTI

注:此库为硬特征,并不符合分析RTTI的标准 但是完全可以正常使用<br> 
通过硬特征分析RTTI(C++ 通过运行时类型信息) 不需要对象指针 暴力取出虚函数<br> 
应用方面:
  * 没有运用到this指针的虚函数 可以直接暴力取出 然后调用<br> 
  * 运用到this指针的虚函数也可以使用来初始化虚函数<br> 
注:你不可能使用InterfaceName来取到虚表

### CPP_VMT_HOOK

通过此库来Hook虚函数!

### CPP_INLINE_HOOK

InlineHook可以Hook CSGO的任意函数!
只要有了地址 就可以Hook
