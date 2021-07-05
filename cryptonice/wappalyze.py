import json
import re
#import warnings
#import requests
import pkg_resources
from bs4 import BeautifulSoup

# Function not needed since the webpage (inc headers, etc) are grabbed in gethttp.py
'''
def _parse_webpage(url):
    global webpage
    webpage = {}
    header_data = {}
    alt_svc_data = {}

    response = requests.get(url, verify=False)

    webpage['url'] = response.url
    webpage['headers'] = response.headers
    webpage['response'] = response.text
    webpage['html'] = BeautifulSoup(response.text, 'html.parser')
    webpage['scripts'] = [script['src'] for script in webpage['html'].findAll('script', src=True)]
    webpage['metatags'] = {meta['name'].lower(): meta['content']
        for meta in webpage['html'].findAll('meta', attrs=dict(name=True, content=True))}

    #print(webpage['response'])
    return webpage
'''

def _prepare_app(app):

    for key in ['url', 'html', 'script', 'implies']:
        try:
            value = app[key]
        except KeyError:
            app[key] = []
        else:
            if not isinstance(value, list):
                app[key] = [value]

    for key in ['headers', 'meta']:
        try:
            value = app[key]
        except KeyError:
            app[key] = {}

    obj = app['meta']
    if not isinstance(obj, dict):
        app['meta'] = {'generator': obj}

    for key in ['headers', 'meta']:
        obj = app[key]
        app[key] = {k.lower(): v for k, v in obj.items()}

    for key in ['url', 'html', 'script']:
        app[key] = [_prepare_pattern(pattern) for pattern in app[key]]

    for key in ['headers', 'meta']:
        obj = app[key]
        for name, pattern in obj.items():
            obj[name] = _prepare_pattern(obj[name])

def _prepare_pattern(pattern):
    regex, _, rest = pattern.partition('\\;')
    try:
        return re.compile(regex, re.I)
    except re.error as e:
        ###warnings.warn("Caught '{error}' compiling regex: {regex}".format(error=e, regex=regex))
        # regex that never matches:
        # http://stackoverflow.com/a/1845097/413622
        return re.compile(r'(?!x)x')


def _has_app(app, webpage):
    for regex in app['url']:
        if regex.search(webpage['url']):
            return True
    for name, regex in app['headers'].items():
        if name in webpage['headers']:
            content = webpage['headers'][name]
            if regex.search(content):
                return True
    for regex in app['script']:
        for script in webpage['scripts']:
            if regex.search(script):
                return True
    for name, regex in app['meta'].items():
        if name in webpage['metatags']:
            content = webpage['metatags'][name]
            if regex.search(content):
                return True
    for regex in app['html']:
        if regex.search(webpage['response']):
            return True

def _get_implied_apps(detected_apps, apps1):

    def __get_implied_apps(detect, apps):
        _implied_apps = set()
        for detected in detect:
            try:
                _implied_apps.update(set(apps[detected]['implies']))
            except KeyError:
                pass
        return _implied_apps

    implied_apps = __get_implied_apps(detected_apps, apps1)
    all_implied_apps = set()

    while not all_implied_apps.issuperset(implied_apps):
        all_implied_apps.update(implied_apps)
        implied_apps = __get_implied_apps(all_implied_apps, apps1)

    return all_implied_apps


def wappalyze(webpage):
    #webpage = _parse_webpage(url)
    obj = json.loads(pkg_resources.resource_string(__name__, "technologies.json"))
    apps = obj['technologies']
    detected = []
    for app_name, app in apps.items():
        _prepare_app(app)
        if _has_app(app, webpage):
            detected.append(app_name)
    detected = set(detected).union(_get_implied_apps(detected, apps))

    category_wise = {}
    for app_name in detected:
        cats = apps[app_name]['cats']
        for cat in cats:
            category_wise[app_name] = obj['categories'][str(cat)]['name']
    inv_map = {}
    for k, v in category_wise.items():
        inv_map[v] = inv_map.get(v, [])
        inv_map[v].append(k)
    return inv_map


if __name__ == '__main__':
    analyzed = wappalyze(_parse_webpage('https://example.com'))
    print (analyzed)
