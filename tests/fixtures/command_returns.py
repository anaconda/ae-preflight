import sys


def ip_addr_show():
    ip_show = (
        '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast '
        'state UP group default qlen 1000'
        '    link/ether 00:0c:29:c5:50:3a brd ff:ff:ff:ff:ff:ff'
        '    inet 10.200.30.165/23 brd 10.200.31.255 scope global '
        'noprefixroute dynamic eth0'
        '       valid_lft 3209sec preferred_lft 3209sec'
        '    inet6 fe80::4319:5db8:2e0a:cbc5/64 scope link noprefixroute'
        '       valid_lft forever preferred_lft forever'
    ).encode('utf-8')
    return ip_show


def ip_addr_show_no_ip():
    ip_show = (
        '3: enP33102p0s2: <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP> mtu '
        '1500 qdisc mq state UP group default qlen 1000\n'
        'link/ether 00:0d:3a:47:72:bd brd ff:ff:ff:ff:ff:ff'
    ).encode('utf-8')
    return ip_show


def distro_release_info(os):
    return_value = {}
    # Check python version and if 3.8 use these returns for distro
    if sys.version_info[:2] > (3, 7):
        if os == 'centos':
            return_value = {
                'codename': 'Core',
                'name': 'CentOS Linux',
                'version_id': '7.5.1804',
                'id': 'centos'
            }
        elif os == 'ubuntu':
            return_value = {
                'codename': 'Xenial Xerus',
                'name': 'Ubuntu',
                'version_id': '16.04.4',
                'id': 'ec2'
            }
        elif os == 'suse':
            return_value = {
                'name': 'SLES',
                'version': '15',
                'codename': '',
                'version_id': '15',
                'pretty_name': 'SUSE Linux Enterprise Server 15',
                'id': 'sles',
                'id_like': 'suse',
                'ansi_color': '0;32',
                'cpe_name': 'cpe:/o:suse:sles:15'
            }
    # If python version 3.7 or below use platform returns
    else:
        if os == 'centos':
            return_value = ('CentOS Linux', '7.5.1804', 'core')
        elif os == 'ubuntu':
            return_value = ('debian', 'stretch/sid', '')
        elif os == 'suse':
            return_value = ('SUSE Linux Enterprise Server', '12', 'x86_64')

    return return_value


def proc_meminfo():
    return (
        'MemTotal:       264119388 kB\n'
        'MemFree:        263359464 kB\n'
        'MemAvailable:   262359452 kB\n'
    ).encode('utf-8')


def getconf_nproc():
    return b'64\n'


def psutil_disk_partitions():
    class DiskPartTest():
        def __init__(self, device, mountpoint, fstype, opts):
            self.device = device
            self.mountpoint = mountpoint
            self.fstype = fstype
            self.opts = opts

    return [
        DiskPartTest('/dev/xvda1', '/', 'xfs', 'rw,inode64,noquota'),
        DiskPartTest('/dev/xvda2', '/boot', 'xfs', 'rw,inode64,noquota'),
        DiskPartTest('/dev/xvda3', '/tmp', 'ext4', 'rw,inode64,noquota'),
        DiskPartTest('/dev/xvda4', '/var', 'ext4', 'rw,inode64,noquota'),
        DiskPartTest(
            '/dev/xvda5',
            '/opt/anaconda',
            'ext4',
            'rw,inode64,noquota'
        )
    ]


def psutil_disk_usage():
    class DiskUsageTest():
        def __init__(self, total, used, free, percent):
            self.total = total
            self.used = used
            self.free = free
            self.percent = percent

    return DiskUsageTest(214422237184, 1679187968, 212743049216, 0.8)


def xfs_info():
    return (
        'meta-data=/dev/xvda2             isize=512    agcount=83, '
        'agsize=636096 blks\n'
        '         =                       sectsz=512   attr=2, projid32bit=1\n'
        '         =                       crc=1        finobt=1 spinodes=0 '
        'rmapbt=0\n'
        '         =                       reflink=0\n'
        'data     =                       bsize=4096   blocks=52351739, '
        'imaxpct=25\n'
        '         =                       sunit=0      swidth=0 blks\n'
        'naming   =version 2              bsize=4096   ascii-ci=0 ftype=1\n'
        'log      =internal               bsize=4096   blocks=2560, '
        'version=2\n'
        '         =                       sectsz=512   sunit=0 blks, '
        'lazy-count=1\n'
        'realtime =none                   extsz=4096   blocks=0, rtextents=0\n'
    ).encode('utf-8')


def lsmod_return():
    return (
        'Module                  Size  Used by\n'
        'iscsi_ibft             16384  0\n'
        'iscsi_boot_sysfs       16384  1 iscsi_ibft\n'
        'af_packet              49152  0\n'
        'cirrus                 28672  1\n'
        'ttm                   114688  1 cirrus\n'
        'intel_rapl             24576  0\n'
        'sb_edac                24576  0\n'
        'intel_powerclamp       16384  0\n'
        'drm_kms_helper        200704  1 cirrus\n'
        'drm                   438272  4 cirrus,ttm,drm_kms_helper\n'
        'crct10dif_pclmul       16384  0\n'
        'crc32_pclmul           16384  0\n'
        'ghash_clmulni_intel    16384  0\n'
        'pcbc                   16384  0\n'
        'drm_panel_orientation_quirks    16384  1 drm\n'
        'aesni_intel           167936  0\n'
        'aes_x86_64             20480  1 aesni_intel\n'
        'crypto_simd            16384  1 aesni_intel\n'
        'syscopyarea            16384  1 drm_kms_helper\n'
        'glue_helper            16384  1 aesni_intel\n'
        'sg                     45056  0\n'
        'scsi_mod              258048  3 libata,scsi_transport_iscsi,sg\n'
        'autofs4                49152  2\n'
        'overlay                69632  0\n'
    ).encode('utf-8')


def all_sysctl_return(skipped=False):
    if skipped:
        return (
            'vm.overcommit_memory = 0'
            '\nnet.bridge.bridge-nf-call-ip6tables = 0'
            '\nnet.bridge.bridge-nf-call-iptables = 0'
            '\nfs.may_detach_mounts = 0'
            '\nfs.inotify.max_user_watches = 8192\n'
        ).encode('utf-8')
    else:
        return (
            'vm.overcommit_memory = 0'
            '\nnet.bridge.bridge-nf-call-ip6tables = 0'
            '\nnet.bridge.bridge-nf-call-iptables = 0'
            '\nfs.may_detach_mounts = 1'
            '\nnet.ipv4.ip_forward = 1'
            '\nfs.inotify.max_user_watches = 1048576\n'
        ).encode('utf-8')


def timedatectl_status(synched=True):
    if synched:
        return (
            'Local time: Mon 2019-05-13 13:17:16 UTC\n'
            'Universal time: Mon 2019-05-13 13:17:16 UTC\n'
            'RTC time: Mon 2019-05-13 13:17:16\n'
            'Time zone: UTC (UTC, +0000)\n'
            'NTP enabled: yes\n'
            'NTP synchronized: yes\n'
            'RTC in local TZ: no\n'
            'DST active: n/a\n'
        ).encode('utf-8')
    else:
        return (
            'Local time: Mon 2019-05-13 13:17:16 UTC\n'
            'Universal time: Mon 2019-05-13 13:17:16 UTC\n'
            'RTC time: Mon 2019-05-13 13:17:16\n'
            'Time zone: UTC (UTC, +0000)\n'
            'NTP enabled: no\n'
            'NTP synchronized: no\n'
            'RTC in local TZ: no\n'
            'DST active: n/a\n'
        ).encode('utf-8')


def timedatectl_status_timesyncd(synched=True):
    if synched:
        return (
            'Local time: Tue 2019-05-14 16:39:56 UTC'
            'Universal time: Tue 2019-05-14 16:39:56 UTC\n'
            'RTC time: Tue 2019-05-14 16:39:56\n'
            'Time zone: Etc/UTC (UTC, +0000)\n'
            'Network time on: yes\n'
            'NTP synchronized: yes\n'
            'RTC in local TZ: no\n'
        ).encode('utf-8')
    else:
        return (
            'Local time: Tue 2019-05-14 16:39:56 UTC'
            'Universal time: Tue 2019-05-14 16:39:56 UTC\n'
            'RTC time: Tue 2019-05-14 16:39:56\n'
            'Time zone: Etc/UTC (UTC, +0000)\n'
            'Network time on: no\n'
            'NTP synchronized: no\n'
            'RTC in local TZ: no\n'
        ).encode('utf-8')


def systemd_ntp_chronyd_status(service):
    if service == 'ntpd':
        return (
            'ntpd.service - Network Time Service\n'
            'Loaded: loaded (/usr/lib/systemd/system/ntpd.service; '
            'disabled; vendor preset: disabled)\n'
            'Active: active (running) since Mon 2019-05-13 15:06:30 UTC;\n'
        ).encode('utf-8')
    elif service == 'chronyd':
        return (
            'chronyd.service - NTP client/server\n'
            'Loaded: loaded (/usr/lib/systemd/system/chronyd.service; '
            'enabled; vendor preset: enabled)\n'
            'Active: active (running) since Mon 2019-05-13 '
            '15:54:02 UTC; 4s ago\nDocs: man:chronyd(8)'
        ).encode('utf-8')
    elif service == 'timesyncd':
        return (
            'systemd-timesyncd.service - Network Time Synchronization\n'
            'Loaded: loaded (/lib/systemd/system/systemd-timesyncd.service;\n'
            'Drop-In: /lib/systemd/system/systemd-timesyncd.service.d\n'
            'Active: active (running) since Tue 2019-05-14 13:58:21 UTC;\n'
        ).encode('utf-8')


def systemd_not_running_status():
    return (
        'ntpd.service - Network Time Service\n'
        'Loaded: loaded (/usr/lib/systemd/system/ntpd.service; '
        'disabled; vendor preset: disabled)\n'
        'Active: inactive (dead) since Mon 2019-05-13 15:53:56 UTC;\n'
    ).encode('utf-8')


def get_pid(pid, name):
    class PidInfoTest():
        def __init__(self, pid, name):
            self.pid = pid
            self.process_name = name

        def name(self):
            return self.process_name

    return PidInfoTest(pid, name)
