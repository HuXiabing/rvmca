# 450.soplex_229 和 450.soplex_4486 源码定位

本文记录两个已确认天然无合法 initial 的 450.soplex 基本块。二者共同特征是：基本块内部把基址寄存器固定为 0，然后访问 `-8(0)`，地址固定为 `0xfffffffffffffff8`。这种访存地址不受寄存器初值、栈槽初值或合成栈布局控制，因此不能通过当前 initial 方法映射到合法栈空间。

说明：当前 soplex 二进制没有可用源码行号调试信息，`addr2line` 只能定位到函数名。下面的源码行号来自函数符号、反汇编和被内联的 `SVector` 方法共同反推。

## 共同背景：SVector 的头部布局

源码：`/home/huxiabing/Documents/source_bb/spec06/SPEC2006/benchspec/CPU2006/450.soplex/src/svector.h`

`SVector` 把实际元素指针 `m_elem` 指向 `elmem[1]`，并把 size/max 放在 `m_elem[-1]` 中：

```cpp
int size() const
{
   if( m_elem != 0 )
      return m_elem[ -1].idx;
   else
      return 0;
}

void set_size(int s)
{
   assert(m_elem != 0);
   m_elem[ -1].idx = s;
}

void setMem(int n, Element* elmem)
{
   assert(n >= 0);

   if (n > 0)
   {
      assert(elmem != 0);
      elmem->val = 0;
      m_elem = &(elmem[1]);
      set_size( 0 );
      set_max ( n - 1 );
   }
   else
      m_elem = 0;
}
```

因此，如果某条异常路径让 `m_elem` 被设为 0 后又继续写 `m_elem[-1].idx`，编译后就会出现固定地址写：

```asm
addi a5,zero,0
sw   ..., -8(a5)
```

这正是这两个基本块无法构造合法 initial 的根因。

## 450.soplex_229

### 对应函数和源码

函数：`soplex::DSVector::setMax(int)`

源码：`/home/huxiabing/Documents/source_bb/spec06/SPEC2006/benchspec/CPU2006/450.soplex/src/dsvector.cc:36`

```cpp
void DSVector::setMax(int newmax)
{
   int siz = size();
   int len = ((newmax < siz) ? siz : newmax) + 1;

   spx_realloc(theelem, len);
   setMem (len, theelem);
   set_size( siz );
}
```

相关声明和调用入口：

- `dsvector.h:57` 的 `makeMem()` 在容量不足时调用 `setMax(size() + n)`。
- `DSVector::operator=(const Vector&)` 在 `dsvector.cc:49` 调用 `setMax(vec.dim())`。
- `DSVector` 被用于 LP 行/列向量、聚合化简中的临时稀疏向量，例如 `spxaggregatesm.cc:235-236` 的 `pcol/prow` 和 `spxaggregatesm.cc:301` 的 `DSVector(tmp)`。

### 对应反汇编

反汇编文件：`/home/huxiabing/Documents/source_bb/spec06/SPEC2006/dis/450.soplex_soplex_base.riscv64.txt`

基本块入口在 `DSVector::setMax(int)+0x90`，即地址 `0x1572c`：

```asm
0x1572c  sd   zero,0(s1)
0x15730  addi a5,zero,0
0x15734  sw   s2,-8(a5)
0x15738  ld   ra,24(sp)
0x1573c  ld   s0,16(sp)
0x15740  ld   s1,8(sp)
0x15744  ld   s2,0(sp)
0x15748  addi sp,sp,32
```

这里 `a5` 被固定为 0，`sw s2,-8(a5)` 的真实地址固定为 `0xfffffffffffffff8`。

### 什么情况下会用到

正常用途是动态稀疏向量 `DSVector` 的容量调整：当赋值、添加非零元、构造临时稀疏向量时，如果当前容量不足，会进入 `DSVector::setMax()` 重新分配内部非零元数组。

但 `450.soplex_229` 这个具体坏块不是正常扩容路径。它对应 `len <= 0` 的异常路径：

```cpp
int len = max(newmax, size()) + 1;
setMem(len, theelem);
set_size(siz);
```

当 `len <= 0` 时，`setMem()` 会把 `m_elem` 设为 0；随后 `set_size(siz)` 仍要写 `m_elem[-1].idx`，就变成 `sw s2,-8(0)`。正常 LP 数据下 `newmax` 和 `size()` 都应是非负容量/大小；进入该块通常意味着容量计算整数溢出、`SVector` 头部元数据被破坏，或调用者传入了不合法的容量。

## 450.soplex_4486

### 对应函数和源码

函数：`soplex::SVSet::xtend(SVector&, int)`

源码：`/home/huxiabing/Documents/source_bb/spec06/SPEC2006/benchspec/CPU2006/450.soplex/src/svset.cc:131`

```cpp
void SVSet::xtend(SVector& svec, int newmax)
{
   if (svec.max() < newmax)
   {
      assert(has(&svec));
      DLPSV* ps = static_cast<DLPSV*>( & svec );

      if (ps == list.last())
      {
         int sz = ps->size();
         ensureMem (newmax - ps->max() + 1);
         insert(memSize(), newmax - ps->max());
         ps->setMem (newmax + 1, ps->mem());
         ps->set_size( sz );
      }
      else
      {
         ensureMem(newmax + 1);
         SVector newps(newmax + 1, &last() + 1);
         int sz = ps->size();
         insert(memSize(), newmax + 1);
         newps = svec;
         ...
         ps->setMem(newmax + 1, newps.mem());
         ps->set_size(sz);
      }
   }
}
```

相关调用入口：

- `svset.cc:174` 和 `svset.cc:180` 的 `SVSet::add2()` 会先调用 `xtend()` 再追加非零元。
- `lpcolset.h:254-262` 的 `LPColSet::xtend()` 直接转调 `SVSet::xtend(colVector_w(...), newmax)`。
- `lprowset.h:260-268` 的 `LPRowSet::xtend()` 直接转调 `SVSet::xtend(rowVector_w(...), newmax)`。
- `spxlp.cc:157` 在把新增行/列同步到另一侧稀疏集合时调用 `p_set.xtend(...)`。
- `spxlp.cc:221` 和 `spxlp.cc:296` 在批量添加行/列时扩展列向量或行向量。

### 对应反汇编

反汇编文件：`/home/huxiabing/Documents/source_bb/spec06/SPEC2006/dis/450.soplex_soplex_base.riscv64.txt`

基本块入口在 `SVSet::xtend(SVector&, int)+0x20c`，即地址 `0x551dc`：

```asm
0x551dc  sd   zero,0(s0)
0x551e0  addi a5,zero,0
0x551e4  sw   s3,-8(a5)
0x551e8  ld   ra,56(sp)
0x551ec  ld   s0,48(sp)
0x551f0  ld   s1,40(sp)
0x551f4  ld   s2,32(sp)
0x551f8  ld   s3,24(sp)
0x551fc  addi sp,sp,64
```

这里 `a5` 同样被固定为 0，`sw s3,-8(a5)` 的真实地址固定为 `0xfffffffffffffff8`。

### 什么情况下会用到

正常用途是扩展 `SVSet` 中某个行/列稀疏向量的非零元容量。SoPlex 的 LP 矩阵同时维护行集合和列集合；添加行、添加列、同步新增非零元时会调用 `SVSet::xtend()`，保证目标 `SVector` 有足够空间。

但 `450.soplex_4486` 这个具体坏块也不是正常扩容路径。它对应 `newmax` 为负或由整数溢出变成负值的异常路径。此时源码中的：

```cpp
ps->setMem(newmax + 1, newps.mem());
ps->set_size(sz);
```

会在 `newmax + 1 <= 0` 时把 `ps->m_elem` 设为 0，然后继续写 `ps->m_elem[-1].idx`，编译后就是 `sw s3,-8(0)`。正常调用下 `newmax` 表示目标非零元容量，应当非负；进入该块通常意味着 `newmax` 计算溢出、`SVector` 的 max/size 元数据异常，或调用者传入了非法容量。

## 对测量工具的结论

这两个块应该继续归为天然不可测，而不是 initial 生成器 bug：

- 它们的失败地址不是来自可控寄存器、栈槽或 load 出来的指针，而是基本块自身把基址固定为 0。
- 即使 initial 任意设置所有 live-in 寄存器和栈内存，`addi a5,zero,0; sw ..., -8(a5)` 的地址仍固定为 `0xfffffffffffffff8`。
- 若强行把这种地址改写到合成栈，会改变基本块原本的异常/不合法状态语义。

