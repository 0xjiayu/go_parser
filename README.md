## A better Golang parser for IDAPro

### 核心功能：

1. 解析 pc line table(**pclntab**)，并从 pclntab 入手解析、恢复**函数符号**，抽取**源码文件列表**；
2. 解析 **strings**；
3. 解析 Interface table(**itab**)
4. 解析 **firstmoduledata**；
5. 根据 firstmoduledata 中的信息，解析所有 **types** 并为 types 各种属性打上有意义的 comment

### 文件列表：

- **go_parser.py** ：整套工具的入口文件，在 IDAPro 中 **[Alt+F7]** 组合键，执行此脚本；
- **common.py**: 通用变量和函数定义；
- **pclntbl.py**: 解析 pc line table(**pclntab**);
- **strings.py**: 解析 strings；
- **moduldata.py**: 解析 **firstmoduledata**；
- **types_builder.py**: 解析所有 **types** ；
- **itab.py**: 解析 Interface Table(**itab**)