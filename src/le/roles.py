import requests
import logging
import ConfigParser
from ConfigParser import NoOptionError, NoSectionError
import argparse
import re


# create logger
log = logging.getLogger('roles')
log.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)
log.addHandler(ch)
config = ConfigParser.ConfigParser()


def pull_logs(account_key, data):
    ts_start = data['ts_start']
    ts_end = data['ts_end']
    results = []
    url = 'https://pull.logentries.com/'+ account_key + \
          '/hosts/DataHub/Default/?start=' + ts_start + '&end=' + ts_end
    req = requests.get(url)
    if req.status_code == 200:
        if len(req.text) > 1:
            for line in req.iter_lines():
                results.append(line)
            return results
        else:
            log.warning('No log data could be found')
    else:
        log.warning('Error pulling logs from server, status_code=%s' % req.status_code)


def get_roles_and_log_files(log_data, data):
    role_regex = data['role_regex']
    log_regex = data['log_regex']
    kvp_value_regex = data['kvp_value_regex']
    roles = set()
    c_role_regex = re.compile(role_regex)
    c_logfile_regex = re.compile(log_regex)
    for log_line in log_data:
        matched_role = c_role_regex.search(log_line)
        matched_log = c_logfile_regex.search(log_line)
        if matched_role.group(0) and matched_log.group(0):
            role_kvp = matched_role.group(0).translate(None, "\"")
            role = re.search(kvp_value_regex, role_kvp).group(0)
            role = role.translate(None, "='")

            log_kvp = matched_log.group(0).translate(None, "\"")
            logfile = re.search(kvp_value_regex, log_kvp).group(0)
            logfile = logfile.translate(None, "='")
            roles.add(role+':'+logfile)
            log.info("Found role and log " + role + ' : ' + logfile)
    return roles


def check_for_existing_logset(account_key, role):
    url = "https://api.logentries.com/%s/hosts/" % account_key
    req = requests.get(url)
    if req.status_code == 200:
        json_response = req.json()
        for host in json_response['list']:
            if host['name'].lower() == role.lower():
                try:
                    host_key = host['key']
                    return host_key
                except ValueError:
                    log.warning('Could not get Host Key')

        return False


def create_logset(account_key, role):
    data = {
        'request': 'register',
        'user_key': account_key,
        'name': role,
        'distver': '',
        'system': '',
        'distname': ''
    }
    log.info('Creating logset ' + role)
    req = requests.post("https://api.logentries.com", data)
    response_json = req.json()
    try:
        host_key = response_json['host_key']
        return host_key
    except ValueError:
        log.warning('Could not get Host Key from response')

    log.info('Request complete ' + req.text)


def create_log(account_key, host_key, log_name):
    data = {
        'request': 'new_log',
        'user_key': account_key,
        'host_key': host_key,
        'name': log_name,
        'type': '',
        'filename': '',
        'retention': '-1',
        'source': 'token'
    }
    log.info('Creating log ' + log_name)
    req = requests.post("https://api.logentries.com", data)
    log.info('Request complete ' + req.text)
    json_req = req.json()
    try:
        token = json_req['log']['token']
        return token
    except ValueError:
        log.warning('Could not obtain log token when creating Log')
        return False


def check_for_log(account_key, host, log_name):
    url = "https://api.logentries.com/"+ account_key+"/hosts/" + host + "/"
    req = requests.get(url)
    if req.status_code == 200:
        json_response = req.json()
        for log_obj in json_response['list']:
            if log_obj['name'].lower() == log_name.lower():
                return True

        return False

def create_rule(account_key, role, kvp, log_token):
    data = {
        'name': role + ' ' + kvp,
        'pattern': '',
        'account_key': account_key,
        'token': log_token,
        'source_tag': '',
        'source_host': '',
    }


def create_connectrion(data, kvps):
    try:
        account_key = data['account_key']
    except ValueError:
        log.warning('Could not get account key')
    for kvp in kvps:
        role = kvp.split(':')[0]
        log_name = kvp.split(':')[1]
        host = check_for_existing_logset(account_key, role)
        if host:
            log.info('Found existing logset for role ' + role)
            if not check_for_log(account_key, host, log_name):
                log.info('Could not find log, creating new Log ' + log_name)
                token = create_log(account_key, host, log_name)
                if token:
                    create_rule(account_key, role, kvp, token)
        else:
            log.info('Logset not found for role' + role + ' creating a new Logset')
            host_key = create_logset(account_key, role)
            token = create_log(account_key, host_key, log_name)
            if token:
                create_rule(account_key, role, kvp, token)



def check_and_create_roles(logs, data):
    roles = get_roles_and_log_files(logs, data)
    create_connectrion(data,roles)


def load_config():
    config.read('roles.ini')


def generate_config():
    config.add_section('Account')
    config.set('Account',"account_key", None)
    config.set('Account',"role_extraction_regex", None)
    config.set('Account',"log_extraction_regex", None)
    config.set('Account',"kvp_value_regex", None)
    config.set('Account',"ts_start", None)
    config.set('Account',"ts_end", None)
    with open('roles.ini', 'w') as configfile:
        config.write(configfile)


def main():
    load_config()
    try:
        account_key = config.get('Account', 'account_key')
        role_regex = config.get('Account', 'role_extraction_regex')
        log_regex = config.get('Account', 'log_extraction_regex')
        kvp_value_regex = config.get('Account', 'kvp_value_regex')
        ts_start = config.get('Account', 'ts_start')
        ts_end = config.get('Account', 'ts_end')
    except NoSectionError, NoOptionError:
        log.error('Could not get value from config')
    data = {'account_key': account_key, 'role_regex': role_regex, 'log_regex': log_regex,
            'kvp_value_regex': kvp_value_regex, 'ts_start': ts_start, 'ts_end': ts_end}
    results = pull_logs(account_key, data)
    if results is not None:
        check_and_create_roles(results, data)

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--generate_config', help='Generates the default roles.ini in the installation directory',
                    action="store_true")
    args = ap.parse_args()
    if args.generate_config:
        generate_config()
    else:
        main()

