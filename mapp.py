from logging import getLogger
from contextlib import suppress
from functools import wraps
from json import load
from logging import getLogger
from os import path
from random import randint
from re import compile as recompile
from re import findall, IGNORECASE
from re import search as research
from re import sub as resub
from time import sleep
from urllib.parse import unquote, urlparse
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from langdetect import detect
from requests import Session
from tld import get_fld

WEBSITES_ENTRIES = []
SHARED_DETECTIONS = []
GENERIC_DETECTION = []
LOG = getLogger("social-analyzer")
SITES_PATH = path.join(path.dirname(__file__), "data", "sites.json")
LANGUAGES_PATH = path.join(path.dirname(__file__), "data", "languages.json")
STRINGS_PAGES = recompile('captcha-info|Please enable cookies|Completing the CAPTCHA', IGNORECASE)
STRINGS_TITLES = recompile('not found|blocked|attention required|cloudflare', IGNORECASE)
STRINGS_META = recompile(r'regionsAllowed|width|height|color|rgba\(|charset|viewport|refresh|equiv', IGNORECASE)
LANGUAGES_JSON = {}
WORKERS = 15
CUSTOM_MESSAGE = 51
WAF = True


def delete_keys(in_object, keys):
    '''
    delete specific keys from object
    '''

    for key in keys:
        with suppress(Exception):
            del in_object[key]
    return in_object


def clean_up_item(in_object, keys_str):
    '''
    delete specific keys from object (user input)
    '''

    with suppress(Exception):
        del in_object["image"]
    if keys_str == "" or keys_str is None:
        with suppress(Exception):
            pass
    else:
        for key in in_object.copy():
            if key not in keys_str:
                with suppress(Exception):
                    del in_object[key]
    return in_object


def check_errors(on_off=None):
    '''
    wrapper function for debugging
    '''

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if on_off:
                try:
                    return func(*args, **kwargs)
                except Exception as err:
                    pass
                    # print(e)
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


def get_language_by_guessing(text):
    '''
    guess language by text, this needs long text
    '''

    with suppress(Exception):
        lang = detect(text)
        if lang and lang != "":
            return LANGUAGES_JSON[lang] + " (Maybe)"
    return "unavailable"


def get_language_by_parsing(source):
    '''
    guess language by parsing the lang tag
    '''

    with suppress(Exception):
        lang = BeautifulSoup(source, "html.parser").find("html", attrs={"lang": True})["lang"]
        if lang and lang != "":
            return LANGUAGES_JSON[lang]
    return "unavailable"


def get_website(site):
    '''
    extract domain from website
    '''

    temp_value = get_fld(site, fix_protocol=True)
    temp_value = temp_value.replace(".{username}", "").replace("{username}.", "")
    return temp_value


@check_errors(True)
def find_username_normal(req, WEBSITES_ENTRIES):
    '''
    main find usernames logic using ThreadPoolExecutor
    '''

    resutls = []

    def fetch_url(site, username, options):
        '''
        this runs for every website entry
        '''
        print(f'Fetching {site}-{username}-{options}')
        sleep(randint(1, 99) / 100)
        LOG.info("[Checking] " + get_fld(site["url"]))
        source = ""

        detection_level = {
            "extreme": {
                "fast": "normal",
                "slow": "normal,advanced,ocr",
                "detections": "true",
                "count": 1,
                "found": 2
            },
            "high": {
                "fast": "normal",
                "slow": "normal,advanced,ocr",
                "detections": "true,false",
                "count": 2,
                "found": 1
            },
            "current": "high"
        }

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0",
        }

        with suppress(Exception):
            session = Session()
            session.headers.update(headers)
            response = session.get(site["url"].replace("{username}", username), timeout=5, verify=False)
            source = response.text
            content = response.content
            answer = dict((k.lower(), v.lower()) for k, v in response.headers.items())
            session.close()
            temp_profile = {}
            temp_detected = {}
            detections_count = 0

            def check_url(url):
                '''
                check if url is okay
                '''

                with suppress(Exception):
                    result = urlparse(url)
                    if result.scheme == "http" or result.scheme == "https":
                        return all([result.scheme, result.netloc])
                return False

            def merge_dicts(temp_dict):
                '''
                '''

                result = {}
                for item in temp_dict:
                    for key, value in item.items():
                        if key in result:
                            result[key] += value
                        else:
                            result[key] = value
                return result

            def detect_logic(detections):
                '''
                check for detections in website entry
                '''

                detections_count = 0
                temp_detected = []
                temp_found = "false"
                temp_profile = {
                    "found": 0,
                    "image": "",
                    "link": "",
                    "rate": "",
                    "status": "",
                    "title": "unavailable",
                    "language": "unavailable",
                    "text": "unavailable",
                    "type": "unavailable",
                    "extracted": "unavailable",
                    "metadata": "unavailable",
                    "good": "",
                    "method": ""
                }
                for detection in detections:
                    temp_found = "false"
                    if detection["type"] in detection_level[detection_level["current"]]["fast"] and source != "":
                        detections_count += 1
                        if detection["string"].replace("{username}", username).lower() in source.lower():
                            temp_found = "true"
                        if detection["return"] == temp_found:
                            temp_profile["found"] += 1
                return temp_profile, temp_detected, detections_count

            def detect():
                '''
                main detect logic
                '''

                temp_profile_all = []
                temp_detected_all = []
                detections_count_all = 0
                for detection in site["detections"]:
                    detections_ = []
                    if detection["type"] == "shared":
                        detections_ = next(item for item in SHARED_DETECTIONS if item["name"] == detection['name'])
                        if len(detections_) > 0:
                            val1, val2, val3 = detect_logic(detections_["detections"])
                            temp_profile_all.append(val1)
                            detections_count_all += val3

                val1, val2, val3 = detect_logic(site["detections"])
                temp_profile_all.append(val1)
                detections_count_all += val3
                return merge_dicts(temp_profile_all), temp_detected_all, detections_count_all

            temp_profile, temp_detected, detections_count = detect()

            if temp_profile["found"] >= detection_level[detection_level["current"]]["found"] and detections_count >= \
                    detection_level[detection_level["current"]]["count"]:
                temp_profile["good"] = "true"

            soup = None

            with suppress(Exception):
                soup = BeautifulSoup(content, "html.parser")

            with suppress(Exception):
                temp_text_arr = []
                temp_text_list = []
                soup = BeautifulSoup(content, "html.parser")
                for item in soup.stripped_strings:
                    if item not in temp_text_list:
                        temp_text_list.append(item)
                        temp_text_arr.append(repr(item).replace("'", ""))
                temp_profile["text"] = " ".join(temp_text_arr)
                temp_profile["text"] = resub(r"\s\s+", " ", temp_profile["text"])
            with suppress(Exception):
                temp_profile["language"] = get_language_by_parsing(source)
                if temp_profile["language"] == "unavailable":
                    temp_profile["language"] = get_language_by_guessing(temp_profile["text"])
            with suppress(Exception):
                temp_profile["title"] = BeautifulSoup(source, "html.parser").title.string
                temp_profile["title"] = resub(r"\s\s+", " ", temp_profile["title"])

            with suppress(Exception):
                temp_matches = []
                temp_matches_list = []
                if "extract" in site:
                    for item in site["extract"]:
                        matches = findall(item["regex"], source)
                        for match in matches:
                            if item["type"] == "link":
                                if check_url(unquote(match)):
                                    parsed = "{}:({})".format(item["type"], unquote(match))
                                    if parsed not in temp_matches:
                                        temp_matches.append(parsed)
                                        temp_matches_list.append({"name": item["type"], "value": unquote(match)})

                if len(temp_matches_list) > 0:
                    temp_profile["extracted"] = temp_matches_list
                else:
                    del temp_profile["extracted"]

            temp_profile["text"] = temp_profile["text"].replace("\n", "").replace("\t", "").replace("\r", "").strip()
            temp_profile["title"] = temp_profile["title"].replace("\n", "").replace("\t", "").replace("\r", "").strip()

            if temp_profile["text"] == "":
                temp_profile["text"] = "unavailable"
            if temp_profile["title"] == "":
                temp_profile["title"] = "unavailable"

            if WAF:
                with suppress(Exception):
                    if 'cf-ray' in answer:
                        temp_profile["text"] = "filtered"
                        temp_profile["title"] = "filtered"
                    elif "server" in answer:
                        if "cloudflare" in answer["server"]:
                            temp_profile["text"] = "filtered"
                            temp_profile["title"] = "filtered"
                    if research(STRINGS_PAGES, temp_profile["text"]):
                        temp_profile["text"] = "filtered"
                        temp_profile["title"] = "filtered"
                    if research(STRINGS_TITLES, temp_profile["title"]):
                        temp_profile["text"] = "filtered"
                        temp_profile["title"] = "filtered"

            with suppress(Exception):
                if detections_count != 0:
                    temp_value = round(((temp_profile["found"] / detections_count) * 100), 2)
                    temp_profile["rate"] = "%" + str(temp_value)
                    if temp_value >= 100.00:
                        temp_profile["status"] = "good"
                    elif temp_value >= 50.00 and temp_value < 100.00:
                        temp_profile["status"] = "maybe"
                    else:
                        temp_profile["status"] = "bad"

            # copied from qeeqbox osint (pypi) project (currently in-progress)

            with suppress(Exception):
                if temp_profile["status"] == "good":
                    temp_meta_list = []
                    temp_for_checking = []
                    soup = BeautifulSoup(content, "lxml")
                    for meta in soup.find_all('meta'):
                        if meta not in temp_for_checking and not research(STRINGS_META, str(meta)):
                            temp_for_checking.append(meta)
                            temp_mata_item = {}
                            add = True
                            if meta.has_attr("property"):
                                temp_mata_item.update({"property": meta["property"]})
                            if meta.has_attr("content"):
                                temp_mata_item.update({"content": meta["content"].replace("\n", "").replace("\t",
                                                                                                            "").replace(
                                    "\r", "").strip()})
                            if meta.has_attr("itemprop"):
                                temp_mata_item.update({"itemprop": meta["itemprop"]})
                            if meta.has_attr("name"):
                                temp_mata_item.update({"name": meta["name"]})

                            with suppress(Exception):
                                if "property" in temp_mata_item:
                                    for i, item in enumerate(temp_meta_list.copy()):
                                        if "property" in item:
                                            if temp_mata_item["property"] == item["property"]:
                                                temp_meta_list[i]["content"] += ", " + temp_mata_item["content"]
                                                add = False
                                elif "name" in temp_mata_item:
                                    for i, item in enumerate(temp_meta_list.copy()):
                                        if "name" in item:
                                            if temp_mata_item["name"] == item["name"]:
                                                temp_meta_list[i]["content"] += ", " + temp_mata_item["content"]
                                                add = False
                                elif "itemprop" in temp_mata_item:
                                    for i, item in enumerate(temp_meta_list.copy()):
                                        if "itemprop" in item:
                                            if temp_mata_item["itemprop"] == item["itemprop"]:
                                                temp_meta_list[i]["content"] += ", " + temp_mata_item["content"]
                                                add = False

                            if len(temp_mata_item) > 0 and add:
                                temp_meta_list.append(temp_mata_item)

                if len(temp_meta_list) > 0:
                    temp_profile["metadata"] = temp_meta_list

            temp_profile["link"] = site["url"].replace("{username}", req["body"]["string"])
            temp_profile["type"] = site["type"]

            if "FindUserProfilesFast" in options and "GetUserProfilesFast" not in options:
                temp_profile["method"] = "find"
            elif "GetUserProfilesFast" in options and "FindUserProfilesFast" not in options:
                temp_profile["method"] = "get"
            elif "FindUserProfilesFast" in options and "GetUserProfilesFast" in options:
                temp_profile["method"] = "all"

            copy_temp_profile = temp_profile.copy()
            return 1, site["url"], copy_temp_profile
        return None, site["url"], []

    for i in range(3):
        WEBSITES_ENTRIES[:] = [d for d in WEBSITES_ENTRIES if d.get('selected') == "true"]
        if len(WEBSITES_ENTRIES) > 0:
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                future_fetch_url = (executor.submit(fetch_url, site, req["body"]["string"], req["body"]["options"]) for
                                    site in WEBSITES_ENTRIES)
                for future in as_completed(future_fetch_url):
                    with suppress(Exception):
                        good, site, data = future.result()
                        if good:
                            WEBSITES_ENTRIES[:] = [d for d in WEBSITES_ENTRIES if d.get('url') != site]
                            resutls.append(data)
                        else:
                            LOG.info("[Waiting to retry] " + get_website(site))

    WEBSITES_ENTRIES[:] = [d for d in WEBSITES_ENTRIES if d.get('selected') == "true"]
    if len(WEBSITES_ENTRIES) > 0:
        for site in WEBSITES_ENTRIES:
            temp_profile = {"link": "",
                            "method": "failed"}
            temp_profile["link"] = site["url"].replace("{username}", req["body"]["string"])
            resutls.append(temp_profile)
    return resutls


@check_errors(True)
def init_detections(detections):
    '''
    load websites_entries, shared_detections and generic_detection
    '''

    temp_list = []
    with open(SITES_PATH, encoding='utf-8') as file:
        for item in load(file)[detections]:
            item["selected"] = "false"
            temp_list.append(item)
    return temp_list


def check_user_cli(username, websites, options, profiles, filter, method):
    '''
    main cli logic
    '''
    print(f'{username}-{websites}')
    WEBSITES_ENTRIES = init_detections("websites_entries")
    temp_detected = {"detected": [], "unknown": [], "failed": []}
    temp_options = "GetUserProfilesFast,FindUserProfilesFast"
    if method != "":
        if method == "find":
            temp_options = "FindUserProfilesFast"
        if method == "get":
            temp_options = "GetUserProfilesFast"

    # req = {"body": {"string": username, "options": temp_options}}
    req = {"body": {"uuid": str(uuid4()), "string": username, "options": temp_options}}
    # setup_logger(uuid=req["body"]["uuid"], file=True, argv=argv)

    if websites == "all":
        for site in WEBSITES_ENTRIES:
            site["selected"] = "true"
    else:
        for site in WEBSITES_ENTRIES:
            for temp in websites.split(","):
                if temp in site["url"]:
                    site["selected"] = "true"

    resutls = find_username_normal(req, WEBSITES_ENTRIES)

    for item in resutls:
        if item is not None:
            if item["method"] == "all":
                if item["good"] == "true":
                    item = delete_keys(item, ["method", "good"])
                    item = clean_up_item(item, options)
                    temp_detected["detected"].append(item)
                else:
                    item = delete_keys(item,
                                       ["found", "rate", "status", "method", "good", "text", "extracted", "metadata"])
                    item = clean_up_item(item, options)
                    temp_detected["unknown"].append(item)
            elif item["method"] == "find":
                if item["good"] == "true":
                    item = delete_keys(item, ["method", "good"])
                    item = clean_up_item(item, options)
                    temp_detected["detected"].append(item)
            elif item["method"] == "get":
                item = delete_keys(item, ["found", "rate", "status", "method", "good", "text", "extracted", "metadata"])
                item = clean_up_item(item, options)
                temp_detected["unknown"].append(item)
            else:
                item = delete_keys(item,
                                   ["found", "rate", "status", "method", "good", "text", "title", "language", "rate",
                                    "extracted", "metadata"])
                item = clean_up_item(item, options)
                temp_detected["failed"].append(item)

    with suppress(Exception):
        print('SETTINGS', profiles, filter)
        if len(temp_detected["detected"]) == 0:
            del temp_detected["detected"]
        else:
            if "all" in profiles or "detected" in profiles:
                if filter == "all":
                    pass
                else:
                    temp_detected["detected"] = [item for item in temp_detected["detected"] if item['status'] in filter]
                if len(temp_detected["detected"]) > 0:
                    temp_detected["detected"] = sorted(temp_detected["detected"],
                                                       key=lambda k: float(k['rate'].strip('%')), reverse=True)
                else:
                    del temp_detected["detected"]
            else:
                del temp_detected["detected"]

        if len(temp_detected["unknown"]) == 0:
            del temp_detected["unknown"]
        else:
            if "all" in profiles or "unknown" in profiles:
                pass
            else:
                del temp_detected["unknown"]

        if len(temp_detected["failed"]) == 0:
            del temp_detected["failed"]
        else:
            if "all" in profiles or "failed" in profiles:
                pass
            else:
                del temp_detected["failed"]

    return temp_detected


from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root(
        username: str = "chris",
        websites: str = "youtube,pinterest,tumblr",
        # mode: str = "fast",
        options: str = "all",  # Show the following when a profile is found: link, rate, titleor text
        method: str = "both",
        # find -> show detected profiles, get -> show all profiles regardless detected or not, both -> combine find & get
        profiles: str = "all",
        # filter profiles by detected, unknown or failed, you can do combine them with comma (detected,failed) or use all
        filter: str = "all"
        # filter detected profiles by good, maybe or bad, you can do combine them with comma (good,bad) or use all
):
    if options == "all":
        options = ""
    return check_user_cli(username=username, websites=websites,
                          options=options, profiles=profiles, filter=filter,
                          method=method)
#
# # if __name__ == "__main__":
# #     uvicorn.run("mapp:app", host="0.0.0.0", port=8081, reload=True)
