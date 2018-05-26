import requests
import base64
import hashlib
from getGithubFiles import getProjectLastCommit, getFileContent
from storageFunctionality import saveFile, createDir, getFile

OAUTH_TOKEN = '0e17c36f9c5cc62945596914fbe6077621bdfc40'
apiKey = '811a31748544dd8d3a2d8a13785c2e78ffb2c351b5d56b37168ab6ff6315dc1f'

def saveProjectFilesToAzure(user, project, limit):
    def saveProjectFilesRecursively(user, project, sha, path, files, dirName, limit):
        resp = requests.get('https://api.github.com/repos/{}/{}/git/trees/{}'.format(user, project, sha), headers={'Authorization': 'token {}'.format(OAUTH_TOKEN)})
        if resp.status_code == 200:
            resp = resp.json()
            tree = resp['tree']
            for content in tree:
                if len(files) == limit:
                        return
                if path != '':
                    newPath = '{}\\{}'.format(path, content['path'])
                else:
                    newPath = content['path']
                if content['type'] == 'blob':
                    files.append(newPath)
                    saveFile(newPath.replace('\\', '-'), getFileContent(content['url']), dirName)
                elif content['type'] == 'tree':
                    dir_sha = content['sha']
                    saveProjectFilesRecursively(user, project, dir_sha, newPath, files, dirName, limit)
    sha = getProjectLastCommit(user, project)
    files = []
    dirName = '{}-{}'.format(user, project)
    createDir(dirName)
    saveProjectFilesRecursively(user, project, sha, '', files, dirName, limit)
    return files

def getAzureFileReport(githubUser, githubProject, fileName):
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
    dirName = '{}-{}'.format(githubUser, githubProject)
    file_ = getFile(dirName, fileName.replace('\\', '-'))
    if file_ == None:
        return 'file not in azure'
    fileText = file_.content.encode('utf-8')
    f = True
    while f:
        report = getReportNoWait(fileName, fileText)
        if report in ['api limit', 'loading']:
            time.sleep(20)
            continue
        f = False
    if report['positives'] > report['total'] // 2:
        return 'infected'
    return 'clean'

if __name__ == '__main__':
    githubUser = 'amandaghassaei'
    githubProject = 'OrigamiSimulator'
    files = saveProjectFilesToAzure(githubUser, githubProject, 6)
    print(files)
    print(getAzureFileReport(githubUser, githubProject, files[5]))