# level00

1. Decompilation with Ghidra

    - Decompile the `level0` binary with Ghidra
    - The binary expects an integer argument that is compared against `0x1a7` (423 in decimal)
    - If the argument matches, it spawns a shell with elevated privileges

2. Analysis of the vulnerability

    The code checks:

    ```c
    iVar1 = atoi(*(char **)(param_2 + 4));
    if (iVar1 == 0x1a7) {  // 0x1a7 = 423
        // Spawns shell with setresgid/setresuid
        execv("/bin/sh",&local_20);
    }
    ```

    The vulnerability is a hardcoded check for a specific numeric value that grants shell access.

3. Exploitation

    ```bash
    ./level1 423
    # Shell spawned with level1 privileges
    cat /home/user/level1/.pass
    ```

4. Token discovered

    The token is : `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`
