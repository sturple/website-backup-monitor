import unittest
import os
import subprocess
import ConfigParser
import time
from datetime import date
from web_backups import create_dir
from web_backups import init
from web_backups import get_section_value
from web_backups import get_database_command
from web_backups import get_site_object
from web_backups import set_archive


class TestUtilityFunctions(unittest.TestCase):
    def test_create_dir(self):
        dir1 ='tests/tmp/a'
        create_dir(dir1)
        self.assertTrue(os.path.isdir(dir1))

    def test_get_section_value(self):
        config, flags, paths = init(config_file, [])
        v = get_section_value(config,'Paths','log_path',False)
        self.assertEqual(v,'test-directory/log/')
        v = get_section_value(config,'Paths','some-fake-path',False)
        self.assertFalse(v)
        # testing default with known Section, but no key
        v = get_section_value(config,'Paths','some-fake-path','fake-path')
        self.assertEqual(v,'fake-path')
        # testing with unknownn section, key.
        v = get_section_value(config,'Fake_Section', 'fake-key', 'fake-value')
        self.assertEqual(v,'fake-value')

    def test_get_section_object(self):
        config = ConfigParser.RawConfigParser()
        config.add_section('example.com')
        config.set('example.com','active','true')
        config.set('example.com','ssh_host','host.example.com')
        config.set('example.com','ssh_user','me')
        config.set('example.com','ssh_key','mykey')
        config.set('example.com','ssh_remote','html,mysql')
        config.set('example.com','database','example-db-1,example-db-2')
        config.add_section('example-db-1')
        config.add_section('example-db-2')
        config.set('example-db-1','name','db1_name')
        config.set('example-db-1','user','db1_user')
        config.set('example-db-1','pass','db1_pass')
        config.set('example-db-1','host','db1_host')
        config.set('example-db-2','name','db2-name')
        config.set('example-db-2','user','db2-user')
        config.set('example-db-2','pass','db2-pass!#$%^&*()')
        config.set('example-db-2','host','localhost')
        obj = get_site_object(config,'example.com')
        self.assertTrue(obj['active'])
        config.set('example.com','active','ff')
        obj = get_site_object(config,'example.com')
        self.assertFalse(obj['active'])
        self.assertEqual(obj['ssh_host'],'host.example.com')
        remote1, remote2 = obj['ssh_remote']
        db1, db2 = obj['database']
        self.assertEquals(db2,'example-db-2')
        self.assertEquals(remote1,'html')

    def test_set_archive(self):
        config_file = 'test/test.cfg';
        config, flags, paths = init(config_file, [])
        tar_dayofweek, tar_restore = set_archive('example.com',paths,True)
        d = date.today()
        filename = 'test-directory/Archives/archive-example.com-dofweek-'+ str(d.isoweekday()) +'.tar.gz';
        self.assertEquals('tar -c test-directory/Websites/example.com/ | gzip -n >%s' %(filename),tar_dayofweek)
        filename = 'test-directory/Archives/month/archive-example.com-month-'+ str(d.month) + '-'+ str(d.day) +'-' + str(d.year)+'.tar.gz'
        self.assertEquals("tar cfz %s test-directory/Archives/" % (filename), tar_restore)
        self.assertEqual(len(set_archive('example.com',paths,False)),1)





class TestConfiguration(unittest.TestCase) :
    global config_file
    config_file = 'test/test.cfg';


    def test_init_flags(self):
        test_args = ['--debug','--no-email']
        config, flags, paths = init(config_file, test_args)
        self.assertTrue('debug' in flags)
        self.assertTrue('no-email' in flags)
        self.assertFalse('no-archive' in flags)
        self.assertFalse('restore-point' in flags)

        test_args = ['--no-archive','--set-restore-point']
        config, flags, paths = init(config_file, test_args)
        self.assertFalse('debug' in flags)
        self.assertFalse('no-email' in flags)
        self.assertTrue('no-archive' in flags)
        self.assertTrue('restore-point' in flags)

    def test_paths(self):
        test_args = []
        config, flags, paths = init(config_file, test_args)
        self.assertEqual('test-directory/log/',paths['log_path'])
        self.assertEqual('test-directory/Websites/',paths['backup_root'])
        self.assertEqual('test-directory/Archives/',paths['archive_root'])
        self.assertEqual('test-directory/Archives/',paths['tmp_path'])


    def test_config(self):
        test_args = []
        config, flags, paths = init(config_file, test_args)
        self.assertEqual(config.get('Paths','root'), 'test-directory')

class TestDatabaseCommands(unittest.TestCase):
    def test_get_database_command(self):
        config, flags, paths = init(config_file, [])
        obj = get_site_object(config,'example.com')
        obj['ssh_key'] = paths['pem_path'] +obj['ssh_key']
        self.assertEqual('test-directory/pem/example.pem',obj['ssh_key'])
        cmd_dir, cmd_mysql1, cmd_mysql2, cmd_chmod = get_database_command(config,obj)
        self.assertEqual('mkdir mysql', cmd_dir)
        self.assertEqual("mysqldump -h internal-example.com -u db-user-1 -p'_-!@#$%^&*()_123456789abcdABCD' db-name-1 > mysql/db-name-1.sql", cmd_mysql1)
        self.assertEqual('chmod -R 755 mysql', cmd_chmod)


if __name__ == '__main__' :
    unittest.main();
