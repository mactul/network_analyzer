# Macéo Tuloup - Analyzeur réseau

Ce projet a pour but de réaliser un outil capable d'analyzer les trames réseau sous Linux et de les afficher d'une façon lisible pour un humain.

- [Macéo Tuloup - Analyzeur réseau](#macéo-tuloup---analyzeur-réseau)
  - [Architecture du Projet](#architecture-du-projet)
  - [Compilation](#compilation)
    - [Qu'est-ce que PowerMake et pourquoi l'avoir utilisé sur ce projet ?](#quest-ce-que-powermake-et-pourquoi-lavoir-utilisé-sur-ce-projet-)
    - [Utilisation de PowerMake](#utilisation-de-powermake)
    - [Warnings du compilateur](#warnings-du-compilateur)
  - [Utilisation du programme](#utilisation-du-programme)
    - [Affichage et taille d'écran](#affichage-et-taille-décran)
    - [Protocoles supportés](#protocoles-supportés)
  - [Sécurité](#sécurité)
    - [Conclusion](#conclusion)


## Architecture du Projet

A la racine du projet, on trouve 2 dossiers:
- lib
- src

`lib` contient:
- la librairie OpenSource [Dash](https://github.com/nothixy/dash) qui a été à l'origine conçue par Valentin Foulon, puis ajustée et fiabilisée par moi. Cette librairie a simplement été copiée ici pour des raison de simplicité mais ne constitue pas un élément du projet à évaluer.
- Les fichiers `common.h` et `common.c` qui contiennent quelques fonctions d'affichages que j'utilise à plusieurs endroits du projet.

`src` contient le code faisant le coeur du programme.
- `main.c` lit la ligne de commande avant de passer la main à la fonction `run_pcap` de `listener.c`
- `listener.c` contient tout le code lié à la librairie pcap. Ce fichier implémente la fonction `run_pcap`, qui ouvre les interfaces (online ou offline) et démarre la capture.
- l'analyse de chaque trame réseau est faite dans `decapsulation.c`, qui se chargera d'appeler les bonnes fonctions pour lire les protocoles de la couche physique, de la couche réseau, puis de la couche transport et enfin de la couche application.
- Les dossiers `*_layer` contiennent les fichiers permettant l'affichage des différents protocoles.
- Vous noterez peut-être la présence d'un fichier `fuzzer.c`, ce fichier n'est pas compilé avec le projet, son role est discuté dans la section [sécurité](#securite).

## Compilation

Bien que je fournisse un Makefile afin d'être assuré que vous parveniez à compiler le projet, ce projet n'a pas été conçu pour être compilé via GNU Make mais via [PowerMake](https://github.com/mactul/powermake), que je vous invite grandement à utiliser.

### Qu'est-ce que PowerMake et pourquoi l'avoir utilisé sur ce projet ?

PowerMake est un outil permettant d'automatiser la compilation, tout comme GNU Make, mais qui offre énormément de fonctionnalités très agréable qui facilite grandement le développement.

PowerMake est un outil que j'ai moi-même développé au cours des 6 derniers mois, je suis très fier de cet outil et c'est pourquoi je voulais l'inclure dans ce projet. Par ailleurs, PowerMake m'apporte énormément de confort dont j'ai maintenant du mal à me débarrasser.

Les fonctionnalités que j'utilise tout particulièrement dans ce projet sont entre autres:
- la compilation de tout les fichiers .c qui correspondent à un pattern bien défini.
- la capacité de compiler en release ou en debug dans différents dossiers avec différentes options de compilation en ajoutant un simple argument sur la ligne de commande
- La traduction de flags de compilateurs, ce qui me permet simplement d'ajouter le flag `-fsecurity`, ce qui active tout les flags compatibles avec mon compilateur permettant d'améliorer la sécurité (Sur ma machine cela représente une trentaine de flags).


### Utilisation de PowerMake

Installer PowerMake se fait aisément via pip (en assumant que python >= 3.7 et pip sont déjà installés).
```sh
pip3 install -U powermake
```

Une fois PowerMake installé, il suffit de lancer `makefile.py` avec `python`:
```sh
python3 makefile.py
```
> [!NOTE]
> Le programme généré se trouvera à l'emplacement `./build/Linux/x64/release/bin/my_wireshark`

Je peux utiliser l'option `-r` pour forcer à tout recompiler, l'option `-v` pour voir les commandes lancées et l'option `-d` pour compiler mon programme en debug:
```sh
python3 makefile.py -rvd
```
> [!NOTE]
> Le programme généré se trouvera à l'emplacement `./build/Linux/x64/debug/bin/my_wireshark`

D'autres options sont disponibles, la liste complète peut être trouvée à l'aide de:
```sh
python3 makefile.py -h
```

### Warnings du compilateur

Je compile mon code sous GCC 14.2 avec énormément de warnings et d'options, certains sont tout nouveaux et encore expérimentaux.

Si vous utilisez un plus vieux compilateur, PowerMake devrait automatiquement retirer les options incompatibles, en revanche, vous pourriez avoir des warnings que je n'ai pas.

En particulier, vous êtes susceptibles d'avoir un warning `-Wcpp` qui se déclenche si votre système ne supporte pas `-D_FORTIFY_SOURCE=3` et descend l'option à la valeur 2.

Vous pourriez également avoir un faux-positif provenant de l'option `-fanalyzer` car dans ses anciennes versions, cette option levait régulièrement des erreurs inexistantes.


## Utilisation du programme

Le programme compilé se trouve dans `./build/Linux/x64/release/bin/my_wireshark` ou `./build/Linux/x64/debug/bin/my_wireshark`.

Pour écouter sur une interface réseau, ce programme nécessite les droits root.  
Vous pouvez donc lancer le programme ainsi:
```sh
sudo ./build/Linux/x64/release/bin/my_wireshark
```
S'il est lancé ainsi, sans argument, le programme vous demandera de sélectionner une interface parmi une liste, puis commencera à afficher les paquets qui passent sur cette interface.

Vous pouvez également lui fournir une interface pour qu'il se lance immédiatement.
```sh
sudo ./build/Linux/x64/release/bin/my_wireshark -i wlan0
```

L'autre mode de fonctionnement est le mode offline, ce mode lit un fichier .cap, .pcap ou .pcapng et affiche les paquets capturés dans ce fichier. Ce mode ne requiert pas les permissions root.
```sh
./build/Linux/x64/release/bin/my_wireshark -o file.pcap
```

Vous pouvez également ajouter un filtre grace à l'option `-f` ou choisir un niveau de verbosité entre 1 et 3 grace à l'option `-v`.  
Finalement, l'option `-h` affiche l'aide.


### Affichage et taille d'écran

En mode verbeux, le programme affiche les données sous la forme d'une sorte de hexdump avec les données en hexadécimal et en ascii à côté.  
Pour faciliter la lecture de cet affichage, le nombre de colones affichée est toujours un multiple de 2, mais cet affichage s'adapte également à la taille du terminal, c'est donc le plus grand multiple de 2 affichable dans l'espace donné de la console.


### Protocoles supportés

Le programme supporte les protocoles:
- Ethernet
- IPv4
- IPv6
- ARP
- ICMP
- ICMPv6
- UDP
- TCP
- SCTP
- DHCP
- DNS
- HTTP(S)
- SMTP(S)
- POP
- IMAP(S)
- Telnet
- FTP(S)

Tout ces protocoles ayant tous de très nombreux cas particuliers, il n'est pas possible d'avoir un jeu de données concis qui couvre tout les cas que j'ai put mettre en place. Le plus petit jeu de données que j'ai put générer qui couvre la majorité de mon code fait 903 fichiers, ce qui n'est pas raisonnable à inclure comme jeu de données de démonstration.

J'inclue donc un jeu de données restreint (demo_files) contenant des fichiers parfois difficile à trouver, permettant de voir une partie raisonnable du travail fourni.

## Sécurité

Tout programme branché sur le réseau est à risque en ce qui concerne la sécurité. C'est d'autant plus vrai pour un programme comme celui-ci, qui analyse des dizaines de protocoles et qui risque rapidement un buffer overflow au détour d'un paquet mal formaté.

Tout au long de l'écriture de ce programme, j'ai essayé de garder cet aspect en tête et de produire un programme le plus fiable possible, voici quelques unes des mesures mises en place:
- Compilation avec le maximum d'options de mitigations des failles de sécurité (ASLR, Full Relro, Stack Canaries, etc...)
- Le code ne fait jamais confiance à la moindre valeur de taille indiquée par les paquets et vérifie toujours que ce qui est indiqué se trouve dans les bornes du buffer.
- Le code a été testé très intensivement à l'aide de fuzzers (explication ci-dessous).

Un fuzzer est un programme qui à partir d'un corpus donné de fichiers valides (ici des fichiers pcap) va pour chaque fichier du corpus, le muter légèrement puis lancer mon programme avec le fichier muté. Si le fichier muté permet d'explorer un nouveau branchement du code, il est ajouté au corpus. Ce processus est répété en boucle, pendant des heures, si bien qu'à la fin, chaque ligne du code source est testée avec toutes sortes de valeurs extravagantes et s'il y a au moins un moyen de faire planter le programme, le fuzzer y parviendra presque assurément au bout d'un moment.

J'ai utilisé 2 fuzzers différents, *LLVM libfuzzer* et *American Fuzzy Loop*, le second étant plus complexe à mettre en place, je ne détaillerais que l'usage du premier.


*LLVM libfuzzer* est intégré à Clang, ce qui fait qu'il peut-être utilisé avec les autres outils d'analyse de Clang, en particulier je l'utilise avec l'address sanitizer de sorte à ce qu'une exception soit générée chaque fois qu'une lecture/écriture est effectuée en dehors des limites du buffer ou bien qu'il y ai un memory leak.  
Pour l'utiliser il suffit de compiler le programme en remplaçant `main.c` par `fuzzer.c` et ajouter les options `fsanitize=address,fuzzer`, le fichier `fuzzer_makefile.py` est là pour faire ça:
```sh
python3 fuzzer_makefile.py -rv
```
Ensuite, il faut lancer le programme en fournissant un corpus de fichiers à muter.
```sh
./build/Linux/x64/release/bin/fuzzer ./pcap_files/
```

Puis on attend un éventuel crash.

### Conclusion

Après plus d'une centaine d'heure à tester mon code a un rythme de 2 millions de fichiers par seconde, sans générer de crash, je peux à présent dire qu'il est improbable qu'il soit possible de faire planter mon code et qu'il est encore plus improbable qu'une faille soit exploitable. Il n'y a donc pas de problème particulier à l'exposer sur le réseau.