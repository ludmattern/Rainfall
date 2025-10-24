#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char output_buffer[54];            /* local_3a */
    build_and_concat(output_buffer);  /* pp(local_3a) */
    puts(output_buffer);
    return 0;
}

/* pp -> build_and_concat
 * param_out : buffer fourni par main (taille 54 dans original)
 */
void build_and_concat(char *param_out)
{
    char ch;
    unsigned int u;
    char *it;
    unsigned char zero_byte = 0;       /* bVar4 = 0 dans l'original (cause pc++ normal) */
    char first_part[20];               /* local_34 */
    char second_part[20];              /* local_20 */

    /* Remplit first_part et second_part avec la fonction p() */
    read_prompted_line(first_part, ">>> ");
    read_prompted_line(second_part, ">>> ");

    /* strcpy(param_out, first_part) -- potentiellement dangereux si first_part n'est pas '\0'-terminé */
    strcpy(param_out, first_part);

    /* boucle équivalente à strlen(param_out) dans l'original */
    u = 0xFFFFFFFF;
    it = param_out;
    do {
        if (u == 0) break;
        u = u - 1;
        ch = *it;
        /* it = it + (uint)zero_byte * -2 + 1  -> ici zero_byte == 0 donc it++ */
        it = it + ((unsigned int)zero_byte * -2) + 1;
    } while (ch != '\0');

    /* (~u - 1) calcule la longueur trouvée (équivalent à strlen) */
    (param_out + (~u - 1))[0] = ' ';
    (param_out + (~u - 1))[1] = '\0';

    /* concaténation sans contrôle de taille */
    strcat(param_out, second_part);

    return;
}

/* p -> read_prompted_line
 * param_dest : buffer de destination (taille 20 dans l'original)
 * prompt : chaîne affichée ( &DAT_080486a0 dans l'original)
 *
 * Comportement : affiche le prompt, lit jusqu'à 0x1000 octets dans un grand tampon,
 * remplace le premier '\n' par '\0', puis strncpy(dest, buffer, 0x14).
 * Attention : strncpy n'ajoute pas le '\0' si l'entrée >= 20 octets.
 */
void read_prompted_line(char *param_dest, const char *prompt)
{
    char *nl;
    char big_read_buffer[4104];

    puts(prompt);
    read(0, big_read_buffer, 0x1000);     /* lit jusqu'à 4096 octets */
    nl = strchr(big_read_buffer, '\n');
    if (nl != NULL) *nl = '\0';
    strncpy(param_dest, big_read_buffer, 0x14); /* copie 20 octets, peut ne pas terminer par '\0' */
    return;
}
