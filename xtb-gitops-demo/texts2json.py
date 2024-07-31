#!/usr/bin/env python3
#
# Translation generator for 4 languages en, de, fr, it.
# * signals that the same text is sued for all languages.
# Use prefixes [EN], [DE], [FR], [IT] if a text needs to be translated still.

import logging
import os
import io
import json
import yaml
import csv
import sys

# input
XTB_TEXTS_JSON = "./texts.json"
XTB_TEXTS_CSV = "/tmp/texts.csv"

# output
XTB_INVENTORY = "./trustbroker-inventories/"

def _main():
    _setup_logging()
    stages = sys.argv[1:]
    if len(stages) == 0:
        stages = ["DEMO"]
    for stage in stages:
        xtbversion = get_xtb_version(stage)
        generate_translations(stage, xtbversion)


def _setup_logging():
    logging.basicConfig(format='%(asctime)s|%(levelname)s: %(message)s', level=logging.INFO)
    # logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# undef so XTB can inject it itself
def get_xtb_version(stage: str):
    return None


def get_language_texts(lang: str, translations: dict):
    langTexts = {}  # key >> lang >> text
    for key, entry in translations.items():
        try:
            langTexts[key] = entry[lang]
        except:
            if not "*" in entry:
                raise Exception(f"Languange item={key} does not have '*' or lang={lang} entry")
            langTexts[key] = entry["*"]
    return langTexts


def optimize_language_texts(translations: dict):
    for key, entry in translations.items():
        if "de" in entry and entry["de"] == entry["en"] and entry["de"] == entry["fr"] and entry["de"] == entry["it"]:
            val = entry["de"]
            translations[key] = dict()
            translations[key]["*"] = val


def write_json(filepath, translation):
    logging.info("Generating file: " + filepath)
    with io.open(filepath, 'w', encoding="utf-8") as jsonFile:
        jsonFile.write(json.dumps(translation, ensure_ascii=False, indent=2, sort_keys=True))


def write_csv(filepath, translations):
    logging.info("Generating file: " + filepath)
    trans = translations.copy() # as we manipulate it
    with io.open(filepath, 'w', encoding="utf-8", newline='\n') as csvFile:
        writer = csv.DictWriter(csvFile, fieldnames=["key", "de", "en", "fr", "it"], delimiter=';', dialect='excel')
        writer.writeheader()
        for key, entry in trans.items():
            entry["key"] = key
            if "*" in entry:
                entry["de"] = entry["*"]
                entry["en"] = entry["*"]
                entry["fr"] = entry["*"]
                entry["it"] = entry["*"]
                del entry["*"]
            writer.writerow(entry)


def generate_translations(stage: str, xtbversion: str):
    # load
    with io.open(XTB_TEXTS_JSON) as jsonFile:
        translations = json.load(jsonFile)
    if xtbversion:
        translations["trustbroker.footer.info.right"]["*"] = xtbversion

    # get rid of redudnat texts
    optimize_language_texts(translations)

    # generate
    targetDir = os.path.abspath(XTB_INVENTORY) + "/" + stage + "/translations/"
    if not os.path.exists(targetDir):
        os.makedirs(targetDir)
    for lang in "en", "de", "fr", "it":
        texts = get_language_texts(lang, translations)
        write_json(targetDir + lang + ".json", texts)

    # dump again, sorting everyting
    write_json(XTB_TEXTS_JSON, translations)

    # CSV for translation interchange
    write_csv(XTB_TEXTS_CSV, translations)


if __name__ == '__main__':
    _main()
