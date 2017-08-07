import ConfigParser
import io
import os
import subprocess
import logging
import paramiko
import time
from datetime import date
from StringIO import StringIO as StringBuffer
import smtplib
import sys
import hashlib

version = subprocess.check_output(['git','rev-parse','--short','HEAD']).strip('\n')

def main() :
    global no_connection
    for section in Config.sections():
        if 'active' in Config.options(section):
            no_connection=False
            logger.info("\r\n")
            logger.info("**********************Section: "+ section+ " **************************" )
            active =get_section_value(section, 'active')
            site_obj = {
                'active'      : True if active.lower() == 'true' else False,
                'section'     : section,
                'ssh_port'    : get_section_value(section,'ssh_port',22),
                'ssh_user'    : get_section_value(section, 'ssh_user'),
                'ssh_host'    : get_section_value(section, 'ssh_host'),
                'ssh_key'     : path['pem_path']+get_section_value(section, 'ssh_key'),
                'ssh_remote'  : get_section_value(section, 'ssh_remote',[]).split(','),
                'ssh_options' : get_section_value(section, 'ssh_options',False),
                'database'    : get_section_value(section,'database',[]).split(','),
            }
            if os.path.isfile(site_obj['ssh_key']):
                do_database(site_obj)
                if no_connection == False:
                    logger.info('Successfull Connection to %s@%s'%(site_obj['ssh_user'],site_obj['ssh_host']))
                    for remote in site_obj['ssh_remote'] :
                        do_rsync(path,site_obj,remote)

                    if 'no-archive' not in flags:
                        set_archive(section,path['backup_root']+site_obj['section']+'/',path['archive_root'],path['tmp_path'])
                    if 'test-connection' in flags or 'dry-run' in flags:
                        ssh_cmd(site_obj,['uname -a', 'readlink -f .'])
            else:
                logger.error('Could Not find Key')
    cmd = "mv -f %s/* %s" %(tmp_path,archive_root);
    logger.info(cmd)
    os.system(cm)


def get_paths() :
    p = {
        'log_path'      : get_section_value('Paths','log_path'),
        'pem_path'      : get_section_value('Paths','pem_path'),
        'backup_root'   : get_section_value('Paths','backup_root'),
        'archive_root'  : get_section_value('Paths','archive_root'),
        'tmp_path'      : get_section_value('Paths','tmp_path')
    }
    for key, path in p.iteritems():
        create_dir(path)
    return p;


def get_section_value(section,key,default=False):
    keys = Config.options(section)
    if key in keys :
        return Config.get(section,key)
    else:
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

def log_command(command):
    stdin, stdout, stderr = command
    try:
        for line in stdout:
            logger.debug(line.strip('\n'))
    except TypeError:
        logger.debug('stdout not iterable')
    try:
        for line in stderr:
            logger.error(line.strip('\n'))
    except TypeError:
        logger.debug('stderr not iterable')
    return stdout

def set_archive(name,directory,archive_dir, tmp_path):
    d = date.today()

    filename = 'archive-'+name+'-dofweek-'+ str(d.isoweekday()) +'.tar.gz';
    yesterday = d.isoweekday() - 1;
    if yesterday <= 0:
        yesterday = 7;
    filename_yesterday = 'archive-'+name+'-dofweek-'+ str(yesterday) +'.tar.gz';
    if not os.path.isdir(archive_dir):
        subprocess.Popen('mkdir -p '+ archive_dir, shell=True);
    #cmd = "tar cfz %s %s" % (archive_dir+filename,directory)
    cmd ="tar -c %s | gzip -n >%s" % (directory,tmp_path+filename)


    logger.debug(cmd);
    if 'dry-run' not in flags:
        (os.system(cmd))


    today_md5 = get_hashs(tmp_path+filename)
    if os.path.isfile(archive_dir+filename_yesterday):
        yesterday_md5 = get_hashs(archive_dir+filename_yesterday)
    else:
        yesterday_md5 = 0
    if today_md5 == yesterday_md5:
        logger.info('Checksums match '+today_md5)
    else:
        logger.warning('Checksums do not match, this can be caused by file updates, or database changes')
        logger.warning(('today',today_md5,'yesterday',yesterday_md5))


    if d.day == 1 or d.day == 15 or 'restore-point' in flags :
        monthly_dir = tmp_path+'month/'
        create_dir(monthly_dir)
        filename = 'archive-'+name+'-month-'+ str(d.month) + '-'+ str(d.day) +'-' + str(d.year)+'.tar.gz'
        cmd = "tar cfz %s %s" % (monthly_dir+filename,directory)
        logger.debug(cmd);
        if 'dry-run' not in flags:
            os.system(cmd)


def do_database(site_obj) :
    cmds = [];
    cmds.append("mkdir mysql")
    for db in site_obj['database'] :
        db_config = {
            'user' : get_section_value(db,'user',False),
            'pass' : get_section_value(db,'pass',False),
            'name' : get_section_value(db,'name',False),
            'host' : get_section_value(db,'host','localhost')
        }
        cmds.append("mysqldump -h %s -u %s -p'%s' %s  > %s" % (db_config['host'],db_config['user'],db_config['pass'], db_config['name'], 'mysql/'+db_config['name']+'.sql'))
        logger.debug('Saving Database '+db_config['name'])
    cmds.append("chmod -R 755 mysql")
    if 'dry-run' not in flags:
        ssh_cmd(site_obj,cmds)


def ssh_cmd(site_obj, cmds) :
    global no_connection
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
    except paramiko.BadHostKeyException as (hostname, got_key,expected_key):
        logger.error('SSH Failed Badhostkey ')
        no_connection = True
    except paramiko.AuthenticationException:
        logger.error('SSH Failed Authentication Error')
        no_connection = True
    except paramiko.SSHException:
        logger.error('SSH Failed SSH Exception')
        no_connection = True
    except:
        logger.error('SSH Unknown Error -- Check Whitelist on Server')
        no_connection = True


def create_dir(path) :
    try:
        if not os.path.isdir(path):
            log_command(subprocess.Popen('mkdir -p '+ path, shell=True))
        return path
    except:
        return False

def do_rsync(path,site_obj,remote):
    rsync_remote = site_obj['ssh_user']+'@'+site_obj['ssh_host']+':'+remote
    rsync_local = path['backup_root']+site_obj['section']
    if not os.path.isdir(rsync_local):
        create_dir(rsync_local)
    rsync_option = site_obj['ssh_key']
    if site_obj['ssh_options'] == 'ssh-dss':
        rsync_option = rsync_option + ' -oHostKeyAlgorithms=+ssh-dss'
    rsync_cmd = "rsync --delete-after  -arz -e 'ssh -i %s' %s %s " % (rsync_option, rsync_remote,rsync_local)
    try:
        logger.debug('rsync '+ rsync_remote)
        if 'dry-run' not in flags:
            os.system(rsync_cmd)
    except:
        logger.error('rsycn failed '+ rsync_cmd);

def send_mail(data, msg):
    d = date.today()
    smtpserver = smtplib.SMTP(data['server'],587)
    smtpserver.ehlo()
    smtpserver.starttls()
    smtpserver.ehlo
    smtpserver.login(data['user'],data['password'])
    header = 'To:' + data['to'] + '\n' + 'From: ' + data['user'] + '\n' + 'Subject:FGMS Backup Results For: '+d.isoformat()+'\n'
    msg = header + msg
    print(msg)
    smtpserver.sendmail(data['user'], data['to'], msg)
    smtpserver.close()

FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logger = logging.getLogger('basic_logger')
if '--debug' in sys.argv :
    logging.basicConfig(level=logging.DEBUG,format=FORMAT)
else:
    logging.basicConfig(level=logging.INFO,format=FORMAT)

Config = ConfigParser.ConfigParser()
Config.read('config/web_backups.cfg')
path = get_paths()
flags = [];
no_connection = False


paramiko.util.log_to_file(path['log_path']+'ssh.log')
logging.getLogger("paramiko").setLevel(logging.WARNING)

### Setup the console handler with a StringIO object
log_capture_string = StringBuffer()
# log_capture_string.encoding = 'cp1251'
ch = logging.StreamHandler(log_capture_string)
if '--debug' in sys.argv :
    ch.setLevel(logging.DEBUG)
else:
    ch.setLevel(logging.INFO)
### Optionally add a formatter
formatter = logging.Formatter(FORMAT)
ch.setFormatter(formatter)

### Add the console handler to the logger
logger.addHandler(ch)
logger.info("\r\n\r\n### Starting Backups Version: %s ####" %(version))

if len(sys.argv) > 0 :
    if '--dry-run' in sys.argv :
        flags.append('dry-run')
        logger.warning('System Is in Dry Run Mode.  --dry-run flag option choosen')
    if '--no-archive' in sys.argv :
        flags.append('no-archive')
        logger.warning('System has turned off archiving.  --no-archive flag option choosen')
    if '--no-email' in sys.argv :
        flags.append('no-email')
        logger.warning('System Email will Not be sent. --no-email flag option choosen')
    if '--test-connection' in sys.argv :
        flags.append('test-connection')
    if '--set-restore-point' in sys.argv :
        flags.append('resort-point')
    if '--debug' in sys.argv :
        flags.append('debug')
logger.info(flags)


main()
logger.info('\r\nFinished backups last step sending email if requested.')
log_capt=log_capture_string.getvalue()
log_capture_string.close()
if 'no-email' not in flags:
    send_mail({
        'to' : get_section_value('mail', 'to','webmaster@fifthgeardev.com'),
        'user' : get_section_value('mail', 'user',False),
        'password' : get_section_value('mail', 'password',False),
        'server' : get_section_value('mail', 'server',False)
    },log_capt)
#print(log_capt)
