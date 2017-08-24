import configparser
import io
import os
import subprocess
import logging
import paramiko
import time
from datetime import date
from io import StringIO as StringBuffer
import smtplib
import sys
import hashlib
import json
from pcloud import PyCloud
try:
    from cStringIO import StringIO      # Python 2
except ImportError:
    from io import StringIO

version = subprocess.check_output(['git','rev-parse','--short','HEAD']).decode().strip('\n')
ipaddress = subprocess.check_output(['dig','+short','myip.opendns.com','@resolver1.opendns.com']).decode().strip('\n')




def main() :
    global connection
    user = get_section_value(config,'pcloud', 'user','')
    pss = get_section_value(config,'pcloud', 'pass','')
    folderid = get_section_value(config,'pcloud', 'folderid',0)
    pc = PyCloud(user,pss)

    for section in config.sections():
        site_obj = get_site_object(config,section)
        logger.debug(site_obj)
        if site_obj['active'] and 'active' in site_obj:
            site_obj['ssh_key'] = paths['pem_path'] +site_obj['ssh_key']
            connection=True
            logger.info("***** Section: "+ site_obj['section'])
            if os.path.isfile(site_obj['ssh_key']):
                if 'dry-run' in flags:
                    ssh_cmd(site_obj,['uname -a', 'readlink -f .'])

                #get database command and then send to ssh_cmd
                cmds = get_database_command(config,site_obj)
                logger.debug(cmds)
                if 'dry-run' not in flags:
                    ssh_cmd(site_obj,cmds)
                # gets set to true each time ssh_cmd is iniated and doesn't have error do all rsync
                if connection == True:
                    logger.info('Successfull Connection to %s@%s'%(site_obj['ssh_user'],site_obj['ssh_host']))
                    for remote in site_obj['ssh_remote'] :
                        cmd = do_rsync(site_obj,paths,remote)
                        logger.debug(cmd)
                        try:
                            if 'dry-run' not in flags:
                                os.system(cmd)
                        except:
                            logger.error('rsycn failed '+ rsync_cmd);

                    if 'no-archive' not in flags:
                        cmds = set_archive(site_obj,paths, 'restore-point' in flags)
                        logger.debug(cmds);
                        if 'dry-run' not in flags:
                            for cmd in cmds:
                                os.system(cmd)

                # if both paths are the same no need to move.
                if (paths['tmp_path'] != paths['archive_root']):
                    #cmd = "rsync -arz  %s %s" %(paths['tmp_path'],paths['archive_root']);
                    send_to_pcloud(site_obj, paths['tmp_path'],pc,folderid)
                    cmd_cleanup = "rm -rf %s*" %(paths['tmp_path']);
                    if 'dry-run' not in flags:
                        #os.system(cmd)
                        os.system(cmd_cleanup)
                    logger.info('cleanup '+cmd_cleanup);




            else:
                logger.error('Could Not find Key')







# gets site object which is cleaned data.
def get_site_object(config,section):
    active = get_section_value(config,section, 'active','false')
    site_obj = {
        'active'      : True if active.lower() == 'true' else False,
        'section'     : section,
        'ssh_port'    : get_section_value(config,section,'ssh_port',22),
        'ssh_user'    : get_section_value(config,section, 'ssh_user'),
        'ssh_host'    : get_section_value(config,section, 'ssh_host'),
        'ssh_key'     : get_section_value(config,section, 'ssh_key'),
        'ssh_remote'  : get_section_value(config,section, 'ssh_remote','').split(','),
        'ssh_options' : get_section_value(config,section, 'ssh_options',False),
        'database'    : get_section_value(config,section,'database','').split(','),
    }
    return site_obj;

# sets up all paths.
def get_paths(config) :
    p = {
        'log_path'      : get_section_value(config,'Paths','log_path'),
        'pem_path'      : get_section_value(config,'Paths','pem_path'),
        'backup_root'   : get_section_value(config,'Paths','backup_root'),
        'archive_root'  : get_section_value(config,'Paths','archive_root'),
        'tmp_path'      : get_section_value(config,'Paths','tmp_path', get_section_value(config,'Paths','archive_root') )
    }
    for key, path in p.items():
        create_dir(path)
    return p;

# gets config section file with error, and defaults.
def get_section_value(config, section,key,default=False):
    try:
        keys = config.options(section)
        if key in keys :
            return config.get(section,key)
        else:
            return default
    except:
        return default

def get_hashs(hash_file):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(hash_file,'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            md5.update(data)
            #sha1.update(data)
    return "MD5: {0}".format(md5.hexdigest())
    #return ["MD5: {0}".format(md5.hexdigest()), "SHA1: {0}".format(sha1.hexdigest())]

def do_command(interface, command,echo=True):
    stdin, stdout, stderr = interface.exec_command(command)
    if echo :
        for line in stdout:
            logger.debug(line.strip('\n'))

def send_to_pcloud(site_obj, tmp_path, pc, folderid):
    subfolders = os.listdir(tmp_path)
    folderlist = pc.listfolder(folderid=folderid)
    #print(folderlist['metadata']['contents'])
    current_folder = {};
    for value in folderlist['metadata']['contents']:
        if (value.get('isfolder')):
            current_folder[value.get('name','')] = value.get('folderid',0)

    for folder in subfolders:
        if folder not in current_folder:
            # creates new folder and its it to current folder list
            results = pc.createfolder(folderid=folderid,name=folder)
            if results['result'] == 0:
                current_folder[folder] =  results['metadata']['folderid']

        pcfilesuploads = []
        for dirpath, dirnames, filenames in os.walk(tmp_path+folder+'/'):
            for n in filenames:
                pcfilesuploads.append(tmp_path+folder+'/'+n)
            for f in pcfilesuploads:
                results = pc.uploadfile(files=[f],folderid=current_folder[folder])
                print(results['result'])
                print(results['metadata'])



def set_archive(site_obj, paths, restore_point_flag):
    name = site_obj['section'];
    directory = paths['backup_root']+name+'/'
    archive_dir = paths['archive_root']
    tmp_path = paths['tmp_path']+name+'/'
    #subfolders = os.listdir(directory)


    d = date.today()
    cmds = []
    filename = 'archive-'+name+'-dofweek-'+ str(d.isoweekday())
    create_dir(tmp_path);
    cmds.append("tar cfz - %s | split --bytes=100MB - %s.tar.gz."% (directory,tmp_path+filename))
    #for folder in subfolders:
    #    filename = 'archive-'+name+'-'+folder+'-dofweek-'+ str(d.isoweekday())
    #    filename = filename.replace('.','-',10);
    #    filename = filename+'.tar.gz'
    #    create_dir(tmp_path);
    #    cmds.append("tar -c %s | gzip -n > %s" % (directory+folder+'/',tmp_path+filename))

    if d.day == 1 or d.day == 15 or restore_point_flag :
        monthly_dir = tmp_path+'month/'
        create_dir(monthly_dir)
        filename = remote+'/'+'archive-'+name+'-month-'+ str(d.month) + '-'+ str(d.day) +'-' + str(d.year)+'.tar.gz'
        cmds.append("tar cfz %s %s" % (monthly_dir+filename,archive_dir))

    return cmds

def get_database_command(config,site_obj) :
    cmds = [];
    cmds.append("mkdir mysql")
    for db in site_obj['database'] :
        db_config = {
            'user' : get_section_value(config,db,'user',False),
            'pass' : get_section_value(config,db,'pass',False),
            'name' : get_section_value(config,db,'name',False),
            'host' : get_section_value(config,db,'host','localhost')
        }
        if db_config['user'] and db_config['pass'] and db_config['name']:
            cmds.append("mysqldump -h %s -u %s -p'%s' %s > %s" % (db_config['host'],db_config['user'],db_config['pass'], db_config['name'], 'mysql/'+db_config['name']+'.sql'))
    cmds.append("chmod -R 755 mysql")
    return cmds



def ssh_cmd(site_obj, cmds) :
    global connection
    try:
        ssh = paramiko.SSHClient();
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(site_obj['ssh_host'],
                    port=int(site_obj['ssh_port']),
                    username=site_obj['ssh_user'],
                    key_filename=site_obj['ssh_key'],
                    timeout=10
                    )
        for cmd in cmds:
            do_command(ssh,cmd, ('test-connection' in flags or 'dry-run' in flags))
        ssh.close()
    except paramiko.AuthenticationException:
        logger.error('SSH Failed Authentication Error')
        connection = False
    except paramiko.SSHException:
        logger.error('SSH Failed SSH Exception')
        connection = False
    except:
        logger.error('SSH Unknown Error -- Check Whitelist on Server')
        connection = False


def create_dir(path) :
    try:
        if not os.path.isdir(path):
            subprocess.Popen('mkdir -p '+ path, shell=True)
        return path
    except:
        return False

def do_rsync(site_obj,paths,remote):
    rsync_remote = site_obj['ssh_user']+'@'+site_obj['ssh_host']+':'+remote
    rsync_local = paths['backup_root']+site_obj['section']
    create_dir(rsync_local)
    rsync_option = site_obj['ssh_key']
    if site_obj['ssh_options'] == 'ssh-dss':
        rsync_option = rsync_option + ' -oHostKeyAlgorithms=+ssh-dss'
    rsync_cmd = "rsync --delete  -arz -e 'ssh -i %s' %s %s " % (rsync_option, rsync_remote,rsync_local)
    return rsync_cmd;


def send_mail(data, msg):
    d = date.today()
    smtpserver = smtplib.SMTP(data['server'],587)
    smtpserver.ehlo()
    smtpserver.starttls()
    smtpserver.ehlo
    smtpserver.login(data['user'],data['password'])
    header = 'To:' + data['to'] + '\n' + 'From: ' + data['user'] + '\n' + 'Subject:FGMS Backup Results For: '+d.isoformat()+'\n'
    if data['cc']:
        header += 'Cc:'+data['cc']+'\n'

    smtpserver.sendmail(data['user'], data['to'],"%s \n\r %s %s" %(header, msg,log_capture_string.getvalue()))
    smtpserver.close()

def init(config_file, params):
    flags = [];
    config = configparser.ConfigParser()
    config.read(config_file)
    paths = get_paths(config)
    if len(params) > 0 :
        if '--dry-run' in params :
            flags.append('dry-run')
        if '--no-archive' in params :
            flags.append('no-archive')
        if '--no-email' in params :
            flags.append('no-email')
        if '--set-restore-point' in params :
            flags.append('restore-point')
        if '--debug' in params :
            flags.append('debug')
    return (config,flags,paths)

if __name__ == '__main__' :
    logger = logging.getLogger('basic_logger')
    log_capture_string = StringBuffer()

    FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    if '--debug' in sys.argv :
        logging.basicConfig(level=logging.DEBUG,format=FORMAT)
    else:
        logging.basicConfig(level=logging.INFO,format=FORMAT)

    config, flags, paths = init('config/web_backups.cfg', sys.argv)

    paramiko.util.log_to_file(paths['log_path']+'ssh.log')
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    # log_capture_string.encoding = 'cp1251'
    ch = logging.StreamHandler(log_capture_string)

    if 'debug' in flags :
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    ### Optionally add a formatter
    formatter = logging.Formatter(FORMAT)
    ch.setFormatter(formatter)

    ### Add the console handler to the logger
    logger.addHandler(ch)



    logger.info(flags)

    connection = True
    logger.info("---> Starting Backups Version: %s @%s" %(version, ipaddress))
    main()
    logger.info('---> Finished backups last step sending email if requested.')

    if 'no-email' not in flags:
        send_mail({
            'to' : get_section_value(config,'mail', 'to','webmaster@fifthgeardev.com'),
            'cc' : get_section_value(config,'mail','cc',False),
            'user' : get_section_value(config,'mail', 'user',False),
            'password' : get_section_value(config,'mail', 'password',False),
            'server' : get_section_value(config,'mail', 'server',False)
        },'')
    log_capture_string.close()
    #print(log_capt)
