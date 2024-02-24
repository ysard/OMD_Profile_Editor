OMD Profile Editor is a savegame editor for Orcs Must Die! Tower Defense game (2011).

Nobody asked for it but here it is anyway;
a proof of concept for editing the game's obfuscated profiles.
After some reverse engineering, it appears that the obfuscation of the file
`profiles.xml` is done by a "simple" substitution of letters.

Currently, only the addition & removal of purchasable profile upgrades are supported.

# Usage

Decrypt usage:

    usage: main.py decrypt [-h] [-p PROFILE] [-r] [-s [SKULL_UPGRADES ...]]

    options:
    -h, --help            show this help message and exit
    -p PROFILE, --profile PROFILE
                          Input profile file. (default: profiles.xml)

    Update SkullUpgrades set:
    -r, --remove          Remove the upgrades (Add by default) (default: False)
    -s [SKULL_UPGRADES ...], --skull-upgrades [SKULL_UPGRADES ...]
                          Enable upgrades to the profiles. Items must be space
                          separated. 1:mur de flèches étendu, 3:barricade
                          améliorée, 4:super baril de bombes, 5:soufre encorcelé,
                          6:baliste auto d'élite, 8:leurre amélioré,
                          12:champion paladin, 13:archer, 14:aplatisseur puissant,
                          15:poussoir amélioré, 16:piège de goudron,
                          19:trampoline de nain, 20:pics à pieux empoisonnés,
                          21:champignon épicé, 22:masse métronome, 24:broyeur
                          autonettoyant, 25:lames murales, 38:presse à monnaie +,
                          39:piege à vapeur, 61:?, 62:?, 63:? (default: ())

Encrypt usage:

    usage: main.py encrypt [-h] [-p PROFILE]

    options:
    -h, --help            show this help message and exit
    -p PROFILE, --profile PROFILE
                            Input profile file. (default: profiles_clear.xml)

# Requirements

Working Python 3.10+ installation (3.6+ if you remove some typing hints).

Dependencies:

    $ pip install argparse
    # or
    $ pip install -r requirements.txt


# Examples

To add the upgrade "masse métronome", first decrypt the profile and add the correct
id to the `-s` argument:

    $ main.py decrypt -s 22 -p <path_to_savegame>/profiles.xml

A readable and editable `profiles_clear.xml` file is created.

Then, encrypt the file and enjoy!

    $ main.py encrypt

# License

GNU Affero General Public License
