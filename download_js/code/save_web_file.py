import shutil

import requests
from bs4 import BeautifulSoup
import os
import csv

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
}


def remove_empty_folders(path_abs):
    walk = list(os.walk(path_abs))
    for path, _, _ in walk[::-1]:
        if len(os.listdir(path)) == 0:
            shutil.rmtree(path)


def get_save_path(name):
    return os.path.join("..\\data\\web_file", name)


def create_dir_if_not_exist(path):
    if not os.path.exists(path):
        os.mkdir(path)


# 保存js
def get_source_js_web(web_url, save_path):
    r = requests.get(web_url, headers=header)
    bs = BeautifulSoup(r.text, "html.parser")
    scripts = bs.find_all("script")
    for i in range(len(scripts)):
        script = scripts[i]
        os_inner_js_path = os.path.join(save_path, "inner_js")
        os_extra_js_path = os.path.join(save_path, "extra_js")

        create_dir_if_not_exist(os_inner_js_path)

        with open(os.path.join(os_inner_js_path, str(i) + ".js"), 'w', encoding="utf8") as code:
            code.write(script.text)
            print("success save one inner js file from " + web_url)

        if script.get("src"):
            create_dir_if_not_exist(os_extra_js_path)
            extra_js_url = script.get("src")

            if not extra_js_url.startswith("https://"):
                extra_js_url = web_url + extra_js_url
            print(extra_js_url)
            r = requests.get(extra_js_url)
            with open(os.path.join(os_extra_js_path, str(i) + ".js"), "wb") as code:
                code.write(r.content)
                print("success save one extra js file from " + web_url)



def save_web_html(web_url, save_path, name):
    r = requests.get(web_url)
    with open(os.path.join(save_path, name), "wb") as code:
        code.write(r.content)


if __name__ == '__main__':
    print("start")

    with open("../data/top-1m.csv") as f:
        count = 0
        urls_reader = csv.reader(f)
        for url in urls_reader:
            url_name = url[1].split(".")[0]
            url_path = get_save_path(url_name)
            os.mkdir(url_path)
            try:
                # 保存网页
                save_web_html("https://" + url[1], url_path, url_name + ".html")

                # 保存js
                get_source_js_web("https://" + url[1], url_path)
                print("finish download js file from " + url[1])
            except requests.exceptions.SSLError as e:
                print(e)
            finally:
                print("----------------")

            count += 1

            if count > 2:
                break

    remove_empty_folders(get_save_path(""))
    print("end")
