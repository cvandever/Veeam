import requests
import logging
import os, json
import pyodbc

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VeeamBackupAPI:
    def __init__(self, server_url, port, username, password):
        self.server_url = server_url
        self.port = port
        self.username = username
        self.password = password
        self.token = self.get_token()

    def base_request(self, full_path, method="GET", data=None):
        try:
            headers = {'x-api-version': '1.1-rev0', 'Content-Type': 'application/json', 'Authorization': f'Bearer {self.token}'}
            r = requests.request(method, full_path, headers=headers, verify=False, data=data)
            return r.json()
        except Exception as e:
            logging.error(e)
            return None

    def get_token(self):
        url = f"{self.server_url}:{self.port}/api/oauth2/token"
        headers = {'x-api-version': '1.1-rev0'}
        data = {'grant_type': 'password', 'username': self.username, 'password': self.password}
        r = requests.post(url, headers=headers, data=data, verify=False)
        return r.json()['access_token']
    
    def get_sessions(self):
        url = f"{self.server_url}:{self.port}/api/v1/sessions"
        return self.base_request(url, "GET")


    def get_backup_config(self):
        url = f"{self.server_url}:{self.port}/api/v1/configBackup"
        return self.base_request(url, "GET")

    def request_certificate(self):
        url = f"{self.server_url}:{self.port}/api/v1/connectionCertificate"
        return self.base_request(url, "POST")

    def get_managed_servers(self):
        url = f"{self.server_url}:{self.port}/api/v1/backupInfrastructure/managedServers?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_backup_repos(self):
        url = f"{self.server_url}:{self.port}/api/v1/backupInfrastructure/repositories?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_sobr_repos(self):
        url = f"{self.server_url}:{self.port}/api/v1/backupInfrastructure/scaleOutRepositories?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_backup_proxies(self):
        url = f"{self.server_url}:{self.port}/api/v1/backupInfrastructure/proxies?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_backup_jobs(self):
        url = f"{self.server_url}:{self.port}/api/v1/jobs?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_job_states(self):
        url = f"{self.server_url}:{self.port}/api/v1/jobs/states"
        return self.base_request(url, "GET")

    def get_credentials(self):
        url = f"{self.server_url}:{self.port}/api/v1/credentials?orderColumn=Name&orderAsc=true"
        return self.base_request(url, "GET")

    def get_credentials_record(self, record_id):
        url = f"{self.server_url}:{self.port}/api/v1/credentials/{record_id}"
        return self.base_request(url, "GET")
    
    def get_encryption_passwords(self):
        url = f"{self.server_url}:{self.port}/api/v1/encryptionPasswords"
        return self.base_request(url, "GET")
    
    def get_backups(self):
        url = f"{self.server_url}:{self.port}/api/v1/backups?orderColumn=Name&orderAsc=false"
        return self.base_request(url, "GET")
    
    def get_backup_objects(self, backup_id):
        url = f"{self.server_url}:{self.port}/api/v1/backups/{backup_id}/objects"
        return self.base_request(url, "GET")
    
    def export_jobs(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/jobs/export"
        return self.base_request(url, "POST")
    
    def import_jobs(self, jobs):
        url = f"{self.server_url}:{self.port}/api/v1/automation/jobs/import"
        return self.base_request(url, "POST", data=jobs)
    
    def export_credentials(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/credentials/export"
        return self.base_request(url, "POST")
    
    def import_credentials(self, creds):
        url = f"{self.server_url}:{self.port}/api/v1/automation/credentials/import"
        return self.base_request(url, "POST", data=creds)
    
    def export_proxies(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/proxies/export"
        return self.base_request(url, "POST")
    
    def import_proxies(self, proxies):
        url = f"{self.server_url}:{self.port}/api/v1/automation/proxies/import"
        return self.base_request(url, "POST", data=proxies)
    
    def export_servers(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/managedServers/export"
        return self.base_request(url, "POST")
    
    def import_servers(self, servers):
        url = f"{self.server_url}:{self.port}/api/v1/automation/managedServers/import"
        return self.base_request(url, "POST", data= servers)
    
    def export_repos(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/repositories/export"
        return self.base_request(url, "POST")
    
    def import_repos(self, repos):
        url = f"{self.server_url}:{self.port}/api/v1/automation/repositories/import"
        return self.base_request(url, "POST", data=repos)
    
    def export_encryption_passwords(self):
        url = f"{self.server_url}:{self.port}/api/v1/automation/encryptionPasswords/export"
        return self.base_request(url, "POST")
    
    def import_encryption_passwords(self, encrypted_creds):
        url = f"{self.server_url}:{self.port}/api/v1/automation/encryptionPasswords/import"
        return self.base_request(url, "POST", data=encrypted_creds)


HostAPI = VeeamBackupAPI("https://veeambackup.lab.ceriumnetworks.com", "9419", os.environ.get("LAB_VEEAM_SVC_BR_USERNAME"), os.environ.get("LAB_VEEAM_SVC_BR_PASSWORD"))

TargetAPI = VeeamBackupAPI("https://veeambackup_tar.lab.ceriumnetworks.com", "9419", os.environ.get("LAB_VEEAM_SVC_BR_USERNAME"), os.environ.get("LAB_VEEAM_SVC_BR_PASSWORD"))

creds = HostAPI.export_credentials()

TargetAPI.import_credentials(json.dumps(creds))

servers = HostAPI.export_servers()

TargetAPI.import_servers(json.dumps(servers))

proxies = HostAPI.export_proxies()

TargetAPI.import_proxies(json.dumps(proxies))

repos = HostAPI.export_repos()

TargetAPI.import_repos(json.dumps(repos))

jobs = HostAPI.export_jobs()

TargetAPI.import_jobs(json.dumps(jobs))

encrypted_creds = HostAPI.export_encryption_passwords()

TargetAPI.import_encryption_passwords(json.dumps(encrypted_creds))

TargetAPI.get_sessions()

sobr_repos = HostAPI.get_sobr_repos()



#credentials need to be created first, password is blanked out need to be added manually.

#servers come next, need to verify there are no blank entries in the json file [ex. {'linuxHosts': [None, None],}]

#proxies come next, need to verify correct here. Recieved error but proxies were created.



"ent_man": {
        "url": ":9398/api/sessionMngr/?v=latest"
    }



class SQLServer:
    def __init__(self, server, database, username, password):
        self.server = server
        self.database = database
        self.username = username
        self.password = password

    def connect(self):
        conn_str = f"DRIVER={{SQL Server}};SERVER={self.server};DATABASE={self.database};UID={self.username};PWD={self.password}"
        conn = pyodbc.connect(conn_str)
        return conn

def execute_query(conn, query):
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    return rows


VeeamSql = SQLServer("veeamsql.lab.ceriumnetworks.com", "VeeamBackup", "sql_admin", "8GxIjZWAEPpvqp9CfnFG")


conn = VeeamSql.connect()

query = "SELECT * FROM [VeeamBackup].[dbo].[Credentials]" # Credetials table

query = "SELECT * FROM [VeeamBackup].[dbo].[ssh_creds]" # ssh_creds table

rows = execute_query(conn, query)

rows
