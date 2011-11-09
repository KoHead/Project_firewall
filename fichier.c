#define TAILLE_MAX 1000 // Tableau de taille 1000
#include <stdio.h> 
#include <stdlib.h>
 
 struct Regle {
     char protocole[5];
     int port;
     int regle;
};
 
 struct Regle* tabRegle = NULL;

/**********************************
* Charge le fichier de configuration en remplissant le tableau global de règles
***********************************/
void load_conf()
{
	FILE* fichier	= NULL;
	struct Regle* tabRegleTemp = NULL;
	
	
    char protocole[5];
    int port;
    char regle[10];
    int nbRegle = 0;
 
    fichier = fopen("fw.conf", "r");
    
    if (fichier != NULL)
    {
    	tabRegle = malloc(sizeof(struct Regle) * 1);
		while (fscanf(fichier, "%s %d %s", protocole, &port, regle) != EOF)
		{
			nbRegle++;
			tabRegleTemp = realloc(tabRegle, sizeof(struct Regle) * (nbRegle + 1));
			if (tabRegleTemp != NULL) // Réallocation réussie
			{
				tabRegle = tabRegleTemp;
				tabRegleTemp = NULL;
				
				tabRegle[nbRegle].protocole = (char*) protocole;
				tabRegle[nbRegle].port = port;
				tabRegle[nbRegle].regle = regle;
				printf("%s %d %s\n", protocole, port, regle);
			}
			
		}
		
		fclose(fichier);
    }
}
