# Website Backups

* This program was created to do Remote Website backups, both file and database
* Uses a configuration file to add ssh host and pem along with database creds.
* Configure Website and Archive folders.
* Website directory is used for Rsync of files from server
* Archive folder is used to create tar.gz files day of week and 1st and 15th snapshots
* checksums are compared with dayofweek current and yesterday for matches.


## Installation
```
git clone https://github.com/sturple/website-backup-monitor.git
pip install paramiko
```

## Options flags

| Flag          |  Description |
| ---------     |  ----------- |
| --dry-run     |  shows actions, test connection, but does not rsycn or tar files|
| --no-email    |  does not send email |
| --no-archive  |  does not archive   |
| --test-connection    | does similar to dry run but test connections |
| --debug       | puts loggin into debug instead of info |


## Running
```
python web_backup.py [options]
```

## Todo

* setup egrep commands to check for base64 code.
* setup ability to pass config file as option.
