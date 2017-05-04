#! /usr/bin/python3

import logging
import logging.handlers
import argparse
import subprocess
import time
import re
import traceback
import os

import pid
import daemon


# Constants

TIME_FORMAT = '%Y-%m-%d_%Hh-%Mm-%Ss'
BACKUP_SUFFIX = 'BACKUP'
SYSLOG_ADDRESS = '/dev/log'
LOGGING_FMT = '%(module)s[%(process)d]:%(levelname)s:%(message)s'
UNIQUE_ID = 'lvm-thin-backup-7e2ce2e4-7274-4a5b-9fda-cdc8e052cfd4'
TMP_DIR = '/tmp'


# Exceptions

class FatalError(RuntimeError):
    pass

class NoRemovableBackupError(RuntimeError):
    pass


# Helpers

def check_output(cmd, **kwargs):
    '''
    Almost the same as subprocess.check_output(), except for some
    default args.

    Return:
    (stdout, stderr)
    '''
    kwargs_ = {
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE,
        'universal_newlines': True
    }
    kwargs_.update(kwargs)
    p = subprocess.Popen(cmd, **kwargs_)
    return p.communicate()


def get_backup_name(lvname):
    return '%s_%s_%s_%s' % (lvname, BACKUP_SUFFIX, time.strftime(TIME_FORMAT), time.time())


def parse_backup_name(snapshot_name):
    match = re.search('^(.*)_([0-9]+(?:\\.[0-9]+)?)$', snapshot_name)
    if not match:
        return
    pos = match.group(1).rfind('_%s_' % BACKUP_SUFFIX)
    if pos == -1:
        return
    origin = match.group(1)[:pos]
    if not check_name(origin):
        return
    try:
        time_ = time.strptime(match.group(1)[pos + len(BACKUP_SUFFIX) + 2:],
                              TIME_FORMAT)
    except ValueError:
        return
    return float(match.group(2))


def check_name(name):
    '''Check whether name is a valid lvm lv or vg name'''
    return re.match(r'^[a-zA-Z0-9+_.][a-zA-Z0-9+_.\-]*$', name) is not None


def lvs(fields):
    '''
    The lvs command.

    Note:
    The returned fields should contain no escaped character
    nor the following:
        ' " \\n
    If the behaviour of lvs changes, this function has to be
    changed accordingly.
    '''
    if isinstance(fields, str):
        fields = [fields]
    fields.append('lv_fullname')
    fields_map = {i.replace('_', ''): i for i in fields}
    cmd = ['lvs', '--noheadings', '--nameprefixes', '-o', ','.join(fields)]
    stdout, stderr = check_output(cmd)
    if stderr:
        logging.warning('lvs wrote something to stderr:\n%s', stderr)
    result = {}
    for line in stdout.splitlines():
        matches = re.findall('''(LVM2_([A-Z_]+)=('[^']*'|"[^"]*"))''', line)
        if re.fullmatch('\\s*' + '\\s+'.join(i[0] for i in matches) + '\\s*',
                        line) is None:
            logging.critical('Parse of lvs output failed: %s', line)
            raise FatalError
        line_result = {fields_map[i[1].lower().replace('_', '')]:
                       i[2][1:-1] for i in matches}
        if set(line_result.keys()) != set(fields):
            logging.critical('lvs did not return all fields queried, '
                             'which is unexpected.')
            raise FatalError
        result[line_result.pop('lv_fullname')] = line_result
    return result


def backup(targets):
    if isinstance(targets, str):
        targets = [targets]
    lvs_output = lvs(['lv_name', 'vg_name', 'lv_attr'])
    failed = False
    for lv_fullname in targets:
        if lv_fullname not in lvs_output:
            logging.error('LV not found: %s', lv_fullname)
            failed = True
        elif lvs_output[lv_fullname]['lv_attr'][0] != 'V':
            logging.error('LV is not thin volume: %s', lv_fullname)
            failed = True
    if failed:
        logging.error('Backup could not start because not all targets are valid')
        return
    for lv_fullname in targets:
        vg_name = lvs_output[lv_fullname]['vg_name']
        lv_shortname = lvs_output[lv_fullname]['lv_name']
        backup_name = get_backup_name(lv_shortname)
        backup_fullname = '%s/%s' % (vg_name, backup_name)
        cmd = ['lvcreate', '-s', lv_fullname, '-n', backup_name, '-y']
        logging.info('Creating snapshot: %s', backup_name)
        stdout, stderr = check_output(cmd)
        if stderr:
            logging.warning('lvcreate wrote something to stderr:\n%s', stderr)
        lvs_output_ = lvs('origin')
        if (backup_fullname not in lvs_output_ or
                lvs_output_[backup_fullname]['origin'] != lv_shortname):
            logging.error('Failed to create snapshot %s for %s',
                          backup_name, lv_fullname)


def release_space(pool_fullname, policy):
    '''
    Remove the oldest backup within the thin pool, whose removal does not
    break the minimum number of backup requirement.
    '''
    lvs_output = lvs(['pool_lv', 'vg_name', 'lv_name', 'origin'])

    # Collect all backups in the thin pool.
    backups = []
    counts = {}
    for lv_fullname, fields in lvs_output.items():
        if '%s/%s' % (fields['vg_name'], fields['pool_lv']) != pool_fullname:
            continue
        timestamp = parse_backup_name(fields['lv_name'])
        if not timestamp:
            continue
        backups.append((timestamp, lv_fullname))
        origin = fields['origin']
        if origin not in counts:
            counts[origin] = 1
        else:
            counts[origin] += 1

    # Remove the oldest removable backup
    backups.sort()
    for timestamp, lv_fullname in backups:
        if time.time() - timestamp < policy.min_time:
            continue
        if counts[lvs_output[lv_fullname]['origin']] <= policy.min_count:
            continue
        cmd = ['lvremove', lv_fullname, '-y']
        stdout, stderr = check_output(cmd)
        if stderr:
            logging.warning('lvremove wrote something to stderr:\n%s',
                            stderr)
        if lv_fullname in lvs([]):
            logging.error('Failed to remove snapshot: %s', lv_fullname)
        break
    else:
        logging.error('No backup can be removed.')
        raise NoRemovableBackupError


def watch(pool_fullname, options, policy):
    if options.interval <= 0:
        logging.error('Interval is smaller than 0: %s.', options.interval)
        return
    if options.limit >= 1 or options.limit <= 0:
        logging.error('Limit is not between 0 and 1: %s.', options.limit)
        return
    while True:
        lvs_output = lvs(['data_percent', 'lv_attr'])
        if pool_fullname not in lvs_output:
            logging.error('Pool not found: %s', pool_fullname)
            return
        fields = lvs_output[pool_fullname]
        if fields['lv_attr'][0] != 't':
            logging.error('Not a thin pool: %s', pool_fullname)
            return
        if float(fields['data_percent']) / 100 > options.limit:
            try:
                release_space(pool_fullname, policy)
            except NoRemovableBackupError:
                time.sleep(options.interval)
        else:
            time.sleep(options.interval)


# Command line interface

def setup_logging(args):
    kwargs = {}
    kwargs['format'] = LOGGING_FMT
    if not args.v:
        kwargs['level'] = logging.ERROR
    elif args.v == 1:
        kwargs['level'] = logging.INFO
    elif args.v >= 2:
        kwargs['level'] = logging.DEBUG
    else:
        raise RuntimeError
    if args.syslog:
        kwargs['handlers'] = [logging.handlers.SysLogHandler(SYSLOG_ADDRESS)]
    elif args.logto:
        kwargs['filename'] = args.logto
    root_logger = logging.getLogger('root')
    while root_logger.handlers:
        root_logger.removeHandler(root_logger.handlers[0])
    logging.basicConfig(**kwargs)


def watch_handler(args):
    setup_logging(args)
    options = argparse.Namespace(interval=args.check_interval, limit=args.limit)
    policy = argparse.Namespace(min_count=args.min_keep_count,
                                min_time=args.min_keep_time)
    if len(args.thin_pool.split('/')) == 2:
        escaped_pool_name = args.thin_pool.replace('-', '--').replace('/', '-')
        if check_name(escaped_pool_name):
            daemon_context = daemon.DaemonContext(
                pidfile=pid.PidFile(
                    '{}.{}'.format(UNIQUE_ID, escaped_pool_name)))
            with daemon_context:
                watch(args.thin_pool, options, policy)
            return
    logging.error('Invalid volume name: %s', args.thin_pool)


def backup_handler(args):
    setup_logging(args)
    if args.vg:
        backup(['%s/%s' % (args.vg, lv) for lv in args.lv])
    else:
        backup(args.lv)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # Common command line options
    common_parser = argparse.ArgumentParser(add_help=False)
    # Logging
    log_options = common_parser.add_mutually_exclusive_group()
    log_options.add_argument('--logto')
    log_options.add_argument('--syslog', action='store_true')
    # Verbosity
    common_parser.add_argument('-v', action='count')

    # Subcommand `watch`
    parser_watch = subparsers.add_parser('watch', parents=[common_parser])
    parser_watch.add_argument('thin_pool')
    parser_watch.add_argument('--limit', '-l', type=float, default=0.9)
    parser_watch.add_argument('--check-interval', '-i', type=float, default=60)
    parser_watch.add_argument('--min-keep-count', '-c', type=int, default=1)
    parser_watch.add_argument('--min-keep-time', '-t', type=float, default=86400)
    parser_watch.set_defaults(func=watch_handler)

    # Subcommand `backup`
    parser_backup = subparsers.add_parser('backup', parents=[common_parser])
    parser_backup.add_argument('--vg')
    parser_backup.add_argument('lv', nargs='+')
    parser_backup.set_defaults(func=backup_handler)

    # Call appropriate handler
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        logging.basicConfig(format=LOGGING_FMT)
        logging.critical('\n%s', traceback.format_exc())

