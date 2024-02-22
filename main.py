#!/usr/bin/env python3
# OMD Profile Editor a savegame editor for Orcs Must Die! Tower Defense game.
# Copyright (C) 2024  Ysard
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
<Profiles lastlogin="%s" version="%d">

</Profiles>

00000000  16 7A 58 45  4C 43 46 4F   59 0A 46 4B  59 5E 46 45
          <  P  r  o   f  i  l  e    s     l  a   s  t  l  o
00000010  4D 43 44 17  08
          g  i  n  =  "

          08 0A 5C 4F  58 59 43 45   44 17 08 1B  08 14
          "     v  e   r  s  i  o    n  =  "  ??  "  >

ooooo1234567890
4545454545 1B 18 19 1E 1F 1C 1D 12 13 1A
           1  2  3  4  5  6  7  8  9  0

eeeeedfghjkmbcx
4F4F4F4F4F 4E 4C 4D 42 40 41 47 48 49 52
           d  f  g  h  j  k  m  b  c  x

iiiiiAZERTYUIOP
4343434343 6B 70 6F 78 7E 73 7F 63 65 7A
           A  Z  E  R  T  Y  U  I  O  P

lllllQSDFGHJKLM
4646464646 7B 79 6E 6C 6D 62 60 61 66 67
           Q  S  D  F  G  H  J  K  L  M

SkullUpgrades
    13 archer
    16 piège de goudron
    15 poussoir amélioré
    20 pics à pieux empoisonnés
    1 mur de flèches étendu
    3 barricade améliorée
    4 super baril de bombes
    5 soufre encorcelé
    6 baliste auto d'élite
    8 leurre amélioré
    25 lames murales
    12 champion paladin
    24 broyeur autonettoyant
    22 masse métronome
    19 trampoline de nain
    21 champignon épicé
    14 aplatisseur puissant
    61 ?
    38 presse à monnaie +
    63 ?
    39 piege à vapeur
    62 ?

    20 16 1  4  13
    3  19 25 15 62
    5  22 12 14 24
    8  6  21 38
"""
# Standard imports
from pathlib import Path
import xml.etree.ElementTree as ET

# Custom imports
import argparse


MAPPING = {
    0x4B: "a",
    0x48: "b",
    0x49: "c",
    0x4E: "d",
    0x4F: "e",
    0x4C: "f",
    0x4D: "g",
    0x42: "h",
    0x43: "i",
    0x40: "j",
    0x41: "k",
    0x46: "l",
    0x47: "m",
    0x44: "n",
    0x45: "o",
    0x5A: "p",
    0x5B: "q",
    0x58: "r",
    0x59: "s",
    0x5E: "t",
    0x5F: "u",
    0x5C: "v",
    0x5D: "w",
    0x52: "x",
    0x53: "y",
    0x50: "z",
    0x6B: "A",
    0x68: "B",
    0x69: "C",
    0x6E: "D",
    0x6F: "E",
    0x6C: "F",
    0x6D: "G",
    0x62: "H",
    0x63: "I",
    0x60: "J",
    0x61: "K",
    0x66: "L",
    0x67: "M",
    0x64: "N",
    0x65: "O",
    0x7A: "P",
    0x7B: "Q",
    0x78: "R",
    0x79: "S",
    0x7E: "T",
    0x7F: "U",
    0x7C: "V",
    0x7D: "W",
    0x72: "X",
    0x73: "Y",
    0x70: "Z",
    # '0x?!': '!',
    # '0x?&': '&',
    0x08: '"',
    0x05: "/",
    0x16: "<",
    0x17: "=",
    0x14: ">",
    0x1A: "0",
    0x1B: "1",
    0x18: "2",
    0x19: "3",
    0x1E: "4",
    0x1F: "5",
    0x1C: "6",
    0x1D: "7",
    0x12: "8",
    0x13: "9",
    0x0A: " ",
    0x23: "\t",
    0x20: "\n",
    # "0x?'": "'",
    # '0x?(': '(',
    # '0x?)': ')',
    # '0x?*': '*',
    # '0x?+': '+',
    0x75: "-",  # ??????
    0x04: ".",
    # '0x??': '?',
    0x56: "_",
}

SKULLUPGRADES = {
    "1": "mur de flèches étendu",
    "3": "barricade améliorée",
    "4": "super baril de bombes",
    "5": "soufre encorcelé",
    "6": "baliste auto d'élite",
    "8": "leurre amélioré",
    "12": "champion paladin",
    "13": "archer",
    "14": "aplatisseur puissant",
    "15": "poussoir amélioré",
    "16": "piège de goudron",
    "19": "trampoline de nain",
    "20": "pics à pieux empoisonnés",
    "21": "champignon épicé",
    "22": "masse métronome",
    "24": "broyeur autonettoyant",
    "25": "lames murales",
    "38": "presse à monnaie +",
    "39": "piege à vapeur",
    "61": "?",
    "62": "?",
    "63": "?",
}


def decrypt(profile, *args, skull_upgrades=None, **kwargs):
    """Decrypt the original profile and export it to a clear XML file"""
    profile_path = Path(profile)
    data = profile_path.read_bytes()

    text = ""
    for byte in data:
        # text += MAPPING.get(byte, " ") #f"x{hex(byte)}")
        text += MAPPING.get(byte, f"|{hex(byte)}|")

    profile_clear_path = Path(profile_path.parent / "profiles_clear.xml")
    profile_clear_path.write_text(text, encoding="utf8")

    if skull_upgrades:
        edit_profile(profile_clear_path, skull_upgrades, *args, **kwargs)


def crypt(profile, *args, **kwargs):
    """Encrypt the clear XML file to a playable profile"""
    profile_clear_path = Path(profile)
    text = profile_clear_path.read_text(encoding="utf8")

    rev_mapping = {v: k for k, v in MAPPING.items()}

    try:
        data = bytes(rev_mapping[char] for char in text)
    except KeyError as e:
        print("Error: Character not known in the charset:", e)
        raise SystemExit(42) from e

    # Make a backup of the previous profile
    crypt_profile = Path(profile_clear_path.parent / "profiles.xml")
    crypt_profile.rename(str(crypt_profile) + ".bak")
    # Write data
    crypt_profile.write_bytes(data)


def get_skull_upgrades(element):
    """Get set of enabled skullupgrades for each profile

    :rtype: <list <set <str>>>
    """
    return {data.text for data in element.iter("Data")}


def show_skull_upgrades(upgrades) -> list:
    """Return list of upgrades significations

    .. warning:: No verification of userland ids
    """
    return [SKULLUPGRADES[upgr] for upgr in upgrades]


def edit_profile(profile_clear_path, skull_upgrades, *args, remove=False, **kwargs):
    """Edit the xml file by adding or removing the given upgrades

    :param skull_upgrades: Iterable of skull upgrade ids.
    :key remove: Remove the given upgrades (Default: False)
    :type remove: <list <str>>
    :type remove: <bool>
    """
    # Cleaning userland data
    skull_upgrades = SKULLUPGRADES.keys() & set(skull_upgrades)

    # Display todo
    alert = "Removing" if remove else "Adding"
    print("{}: '{}'".format(alert, "', '".join(show_skull_upgrades(skull_upgrades))))

    # Modification of XML Element Tree
    tree = ET.parse(profile_clear_path)
    root = tree.getroot()

    for profile in root.iter("Profile"):
        print("Current profile name:", profile.get("name"))

        for entry in root.iter("Entry"):
            if entry.get("key") == "SkullUpgrades":
                upgrades = get_skull_upgrades(entry)

                if remove:
                    upgrades -= skull_upgrades
                else:
                    upgrades.update(skull_upgrades)

                # Clear current data elements
                entry.clear()

                # Replace by updated set of upgrades
                for upgrade in upgrades:
                    ET.SubElement(entry, "Data").text = upgrade

                # print("new upgrades:", upgrades)
                # print(entry.attrib, upgrades)
                # for data in entry.iter("Data"):
                #     print(data.text)
                current_state = "'{}'".format(
                    "', '".join(show_skull_upgrades(upgrades))
                )

                print(current_state)
                print("skullUpgrades updated!")


def args_to_param(args):
    """Return argparse namespace as a dict {variable name: value}"""
    return {k: v for k, v in vars(args).items() if k not in ("func", "verbose")}


def main():
    """Entry point and argument parser"""
    parser = argparse.ArgumentParser()

    # Subparsers
    subparsers = parser.add_subparsers(title="subcommands")

    parser_decrypt = subparsers.add_parser(
        "decrypt",
        help=decrypt.__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_decrypt.add_argument(
        "-p",
        "--profile",
        help="Input profile file.",
        default="profiles.xml",
    )
    parser_decrypt.set_defaults(func=decrypt)

    skull_group = parser_decrypt.add_argument_group(title="Update SkullUpgrades set")
    skull_group.add_argument(
        "-r",
        "--remove",
        help="Remove the upgrades (Add by default)",
        action="store_true",
    )
    skull_group.add_argument(
        "-s",
        "--skull-upgrades",
        help="Enable upgrades to the profiles. Items must be space separated. "
        + ", ".join(":".join(item) for item in SKULLUPGRADES.items()),
        nargs="*",
        default=tuple(),
    )

    parser_encrypt = subparsers.add_parser(
        "encrypt",
        help=crypt.__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_encrypt.set_defaults(func=crypt)
    parser_encrypt.add_argument(
        "-p", "--profile", help="Input profile file.", default="profiles_clear.xml"
    )

    # Get program args and launch associated command
    args = parser.parse_args()
    if "func" not in dir(args):
        # Nor argument
        parser.print_usage()
        raise SystemExit(1)

    args.func(**args_to_param(args))


if __name__ == "__main__":
    main()
