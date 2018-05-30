import twitter
import requests
import base64
from urlextract import URLExtract
import time
import re
import hashlib
from getGithubFiles import getProjectLastCommit, getFileContent
from storageFunctionality import saveFile, createDir, getFile
import threading


OAUTH_TOKEN = '8e4d34d7ca24dcbf4df518b2419fb3ed72cd2dd2'
apiKey = '811a31748544dd8d3a2d8a13785c2e78ffb2c351b5d56b37168ab6ff6315dc1f'
account_name = "akras14"
githubUser = 'ingridstoleru'
limit = 10

def getUserTweets(account_name):
    api = twitter.Api(consumer_key='og0R0hgBR7TZDuvWiiRMAdaJn',
    consumer_secret='XvDnJGgTQ6jRwJFTp3D4LlutMSAmu0SoK1lAiZWu2YOvHRriTK',
    access_token_key='750821522479181824-tOJiIbWX01gPoVsVadtmOKgno3tFuF8',
    access_token_secret='FB9Py94PpcBCzMqaqZuwDhws7QbRI6B2XLK2f1igOiS1X')

    #print(api.VerifyCredentials())
    tweets = api.GetUserTimeline(screen_name=account_name, count=limit)
    #tweets = [i.AsDict() for i in t]
    return tweets


def getUrlsFromTweet(tweet):
    extractor = URLExtract()
    urls = extractor.find_urls(tweet)
    return urls

def getUrlStatus(url):
    def scan(url):
        resp = requests.post('https://www.virustotal.com/vtapi/v2/url/scan?apikey={}'.format(apiKey), params={'url': url})
        if resp.status_code == 204:
            return 'api limit'
        if resp.status_code != 200:
            return None
        resp = resp.json()
        if resp['response_code'] != 1:
            return None
        return 'loading'
    def getReportNoWait(url):
        resp = requests.post('https://www.virustotal.com/vtapi/v2/url/report?apikey={}'.format(apiKey), params={'resource': url})
        if resp.status_code == 204:
            return 'api limit'
        if resp.status_code != 200:
            return None
        resp = resp.json()
        if resp['response_code'] == 1:
            return resp
        elif resp['response_code'] == -2:
            return 'loading'
        else:
            return scan(url)
    f = True
    while f:
        report = getReportNoWait(url)
        if report in ['api limit', 'loading']:
            time.sleep(20)
            continue
        f = False
    if report['positives'] > report['total'] // 2:
        return 'infected'
    return 'clean'


def getUserProjects(user):
    resp = requests.get('https://api.github.com/users/{}/repos'.format(user), headers={'Authorization': 'token {}'.format(OAUTH_TOKEN)})
    if resp.status_code != 200:
        return []
    resp = resp.json()
    projects = [project['name'] for project in resp]
    return projects

    
    t = time.time()
    files = saveProjectFilesToAzure(githubUser, githubProject, 3)
    print(files)
    print(time.time() - t)
    t = time.time()
    files = saveProjectFilesToAzure2(githubUser, githubProject, 3)
    print(files)
    print(time.time() - t)

def saveProjectFilesToAzure(user, project, limit):
    def saveProjectFilesRecursively(user, project, sha, path, files, dirName, limit):
        #print('https://api.github.com/repos/{}/{}/git/trees/{}'.format(user, project, sha))
        resp = requests.get('https://api.github.com/repos/{}/{}/git/trees/{}'.format(user, project, sha), headers={'Authorization': 'token {}'.format(OAUTH_TOKEN)})  
        #print(resp.status_code)
        if resp.status_code == 200:
            resp = resp.json()
            tree = resp['tree']
            trees = []
            blobs = []
            for t in tree:
                if t['type'] == 'blob':
                    blobs.append(t)
                else:
                    trees.append(t)
            for content in blobs:
                if len(files) == limit:
                    return 1
                if content['path'] in [".gitignore", "LICENSE", "README.md"]:
                    continue
                if path != '':
                    newPath = '{}\\{}'.format(path, content['path'])
                else:
                    newPath = content['path']
                dir_sha = content['sha']
                #print("here" + newPath)
                files.append(newPath)
                t = threading.Thread(target=saveFile, args=[newPath.replace('\\', '-'), getFileContent(content['url']), dirName])
                t.setDaemon(False)
                t.start()
            for content in trees:
                if len(files) == limit:
                        return 1
                if path != '':
                    newPath = '{}\\{}'.format(path, content['path'])
                else:
                    newPath = content['path']
                dir_sha = content['sha']
                if saveProjectFilesRecursively(user, project, dir_sha, newPath, files, dirName, limit) == 1:
                    return 1
            return 0
    sha = getProjectLastCommit(user, project)
    #print('sha: ', sha)
    files = []
    dirName = '{}-{}'.format(user, project)
    t = threading.Thread(target=createDir, args=[ dirName])
    t.setDaemon(False)
    t.start()
    saveProjectFilesRecursively(user, project, sha, '', files, dirName, limit)
    return files

def saveProjectFilesToAzure2(user, project, limit):
    def saveProjectFilesRecursively2(user, project, path, files, dirName, limit):
        url = 'https://api.github.com/repos/{}/{}/contents/{}'.format(user, project, path)
        resp = requests.get(url, headers={'Authorization': 'token {}'.format(OAUTH_TOKEN)})  
        #print(resp.status_code)
        if resp.status_code == 200:
            resp = resp.json()
            dirs = []
            blobs = []
            for t in resp:
                if t['type'] == 'file':
                    blobs.append(t)
                elif t['type'] == 'dir':
                    dirs.append(t)
                else:
                    continue
            for content in blobs:
                if len(files) == limit:
                    return 1
                if content['name'] in [".gitignore", "LICENSE", "README.md"]:
                    continue
                files.append(content['path'])
                t = threading.Thread(target=saveFile, args=[content['path'].replace('/', '-'), getFileContent(content['_links']['git']), dirName])
                t.setDaemon(False)
                t.start()
            for content in dirs:
                if len(files) == limit:
                        return 1
                if saveProjectFilesRecursively2(user, project, content['path'], files, dirName, limit) == 1:
                    return 1
            return 0
    #print('sha: ', sha)
    files = []
    dirName = '{}-{}'.format(user, project)
    t = threading.Thread(target=createDir, args=[ dirName])
    t.setDaemon(False)
    t.start()
    saveProjectFilesRecursively2(user, project, '', files, dirName, limit)
    return files

def getFile(dirName, fileName):
    file_ = fileService.get_file_to_text(filesDir, dirName, fileName)
    return file_

def getProjectFiles(user, project, limit):
    sha = getProjectLastCommit(user, project)
    files = []
    getProjectFilesRecursively(user, project, sha, files, limit)
    for i in range(len(files)):
        content = getFileContent(files[i]['url'])
        files[i]['content'] = content
    return files

def getProjectFilesRecursively(user, project, sha, files, limit):
    resp = requests.get('https://api.github.com/repos/{}/{}/git/trees/{}'.format(user, project, sha), headers={'Authorization': 'token {}'.format(OAUTH_TOKEN)})
    if resp.status_code == 200:
        resp = resp.json()
        tree = resp['tree']
        for content in tree:
            if len(files) == limit:
                    return
            if content['type'] == 'blob':
                files.append({'path': content['path'], 'url': content['url'], 'size': content['size'], 'sha': content['sha']})
            elif content['type'] == 'tree':
                dir_sha = content['sha']
                getProjectFilesRecursively(user, project, dir_sha, files, limit)


def getAzureFileReport(githubUser, githubProject, fileName):
    if githubUser == "nada" or githubProject == "nada" or fileName == "nada":
        return "Please provide all the fields!"
    def scan(fileName, fileText, wait=False):
        resp = requests.post('https://www.virustotal.com/vtapi/v2/file/scan?apikey={}'.format(apiKey), files={'file': (fileName, fileText)})
        if resp.status_code == 204:
            return 'api limit'
        if resp.status_code != 200:
            return None
        resp = resp.json()
        if resp['response_code'] != 1:
            return None
        fileSha = resp['sha1']
        if wait == True:
            return getReportWait(fileName, fileText)
        return 'loading'
    def getReportNoWait(fileName, fileText):
        h = hashlib.sha1()
        h.update(fileText)
        fileSha = h.hexdigest()
        resp = requests.post('https://www.virustotal.com/vtapi/v2/file/report?apikey={}&resource={}'.format(apiKey, fileSha))
        if resp.status_code == 204:
            return 'api limit'
        if resp.status_code != 200:
            return None
        resp = resp.json()
        if resp['response_code'] == 1:
            return resp
        elif resp['response_code'] == -2:
            return 'loading'
        else:
            return scan(fileName, fileText, False)
    try:
        dirName = '{}-{}'.format(githubUser, githubProject)
        file_ = getFile(dirName, fileName.replace('\\', '-').replace('/', '-'))
        if file_ == None:
            return 'file not in azure'
        fileText = file_.content.encode('utf-8')
        f = True
        while f:
            report = getReportNoWait(fileName, fileText)
            print(report)
            if report in ['api limit', 'loading']:
                time.sleep(20)
                continue
            f = False
        if report['positives'] > report['total'] // 2:
            return 'The sample is infected!'
        return 'clean!'
    except:
        return 'clean!'


if __name__ == "__main__":
    all_urls = []
    all_files = []
    """ Get all urls from the all the tweets of a user """
    for el in getUserTweets(account_name):
        for url in getUrlsFromTweet(str(el)):
            all_urls.append(url)       
    #print(all_urls)
    #for el in all_urls:
        #print(getUrlStatus(el))
    all_projects = getUserProjects(githubUser)
    t = time.time()
    for githubProject in all_projects:
        for file_s in getProjectFiles(githubUser, githubProject, 1):
            all_files.append(file_s)
        files = saveProjectFilesToAzure(githubUser, githubProject, 3)
        files = saveProjectFilesToAzure2(githubUser, githubProject, 3)
    for file_s in all_files:
        print(getAzureFileReport(githubUser, githubProject, file_s))
        


