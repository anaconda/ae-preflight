
def os_return(distro):
    if distro == 'rhel':
        return_value = {
            'distribution': 'centos',
            'version': '7.5',
            'dist_name': 'CentOS Linux',
            'based_on': 'rhel'
        }
    elif distro == 'ubuntu':
        return_value = {
            'distribution': 'ec2',
            'version': '16.04',
            'dist_name': 'Ubuntu',
            'based_on': 'debian'
        }
    elif distro == 'suse':
        return_value = {
            'distribution': 'sles',
            'version': '12',
            'dist_name': 'SLES',
            'based_on': 'suse'
        }

    return return_value


def system_compatability(test_pass=True):
    if test_pass:
        return {
            'OS': 'PASS',
            'version': 'PASS'
        }

    return {
        'OS': 'PASS',
        'version': 'FAIL'
    }


def memory_cpu(test_pass=True):
    if test_pass:
        return {
            'memory': {
                'minimum': 16.0,
                'actual': 251.88
            },
            'cpu_cores': {
                'minimum': 8,
                'actual': 64
            }
        }

    return {
        'memory': {
            'minimum': 16.0,
            'actual': 14.88
        },
        'cpu_cores': {
            'minimum': 8,
            'actual': 4
        }
    }


def mounts(test_pass=True):
    if test_pass:
        return {
            '/': {
                'recommended': 302.0,
                'free': 498.13,
                'total': 499.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'xfs',
                'ftype': '1'
            },
            '/tmp': {
                'recommended': 30.0,
                'free': 39.13,
                'total': 39.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
        }

    return {
        '/': {
            'recommended': 2.0,
            'free': 19.13,
            'total': 19.7,
            'mount_options': 'rw,inode64,noquota',
            'file_system': 'xfs',
            'ftype': '0'
        },
        '/tmp': {
            'recommended': 30.0,
            'free': 19.13,
            'total': 19.7,
            'mount_options': 'rw,inode64,noquota',
            'file_system': 'ext4'
        },
        '/opt/anaconda': {
            'recommended': 100.0,
            'free': 98.13,
            'total': 99.7,
            'mount_options': 'rw,inode64,noquota',
            'file_system': 'ext4'
        },
        '/var': {
            'recommended': 200.0,
            'free': 98.13,
            'total': 99.7,
            'mount_options': 'rw,inode64,noquota',
            'file_system': 'ext4'
        }
    }


def resolv_conf(test_pass=True):
    if test_pass:
        return {
            'search_domains': ['test.domain', 'another.domain'],
            'options': []
        }

    return {
        'search_domains': [
            'test.domain',
            'another.domain',
            'again.domain',
            'optional.domain'
        ],
        'options': ['timeout:2', 'rotate']
    }


def resolv_conf_warn():
    return {
        'search_domains': ['test.domain', 'another.domain'],
        'options': ['rotate']
    }


def ports(test_pass=True):
    if test_pass:
        return {
            'eth0': {
                '80': 'open',
                '443': 'open',
                '32009': 'open',
                '61009': 'open',
                '65535': 'open'
            }
        }

    return {
        'eth0': {
            '80': 'open',
            '443': 'closed',
            '32009': 'closed',
            '61009': 'closed',
            '65535': 'closed'
        },
        'eth1': 'No IP address assigned'
    }


def agents(test_pass=True):
    if test_pass:
        return {'running': []}

    return {'running': ['puppet-agent']}


def modules(test_pass=True):
    if test_pass:
        return {
            'missing': [],
            'enabled': [
                'iptable_filter',
                'br_netfilter',
                'iptable_nat',
                'ebtables',
                'overlay'
            ]
        }

    return {
        'missing': [
            'iptable_filter',
            'br_netfilter',
            'iptable_nat',
            'ebtables'
        ],
        'enabled': ['overlay']
    }


def sysctl(test_pass=True):
    if test_pass:
        return {
            'enabled': [
                'net.bridge.bridge-nf-call-ip6tables',
                'net.bridge.bridge-nf-call-iptables',
                'fs.inotify.max_user_watches',
                'fs.may_detach_mounts',
                'net.ipv4.ip_forward'
            ],
            'incorrect': {},
            'disabled': [],
            'skipped': []
        }

    return {
        'enabled': ['net.ipv4.ip_forward'],
        'disabled': [
            'net.bridge.bridge-nf-call-ip6tables',
            'net.bridge.bridge-nf-call-iptables'
        ],
        'incorrect': {
            'fs.inotify.max_user_watches': '8192'
        },
        'skipped': [
            'fs.may_detach_mounts'
        ]
    }


def selinux(test_pass=True):
    if test_pass:
        return {
            'getenforce': 'disabled',
            'config': 'permissive'
        }

    return {
        'getenforce': 'disabled',
        'config': 'enforcing'
    }


def infinity(test_pass=True):
    if test_pass:
        return True

    return False


def check_dirs(test_pass=True):
    if test_pass:
        return []
    else:
        return [
            '/etc/chef',
            '/etc/salt',
            '/etc/puppet'
        ]


def ntp_check(process, test_pass=True):
    if process == 'ntpd':
        if test_pass:
            return {
                'using': 'NTP',
                'installed': True,
                'enabled': True,
                'synched': True
            }
        else:
            return {
                'using': None,
                'installed': 'ntpd',
                'enabled': False,
                'synched': False
            }
    elif process == 'chronyd':
        if test_pass:
            return {
                'using': 'chronyd',
                'installed': True,
                'enabled': True,
                'synched': True
            }
        else:
            return {
                'using': None,
                'installed': 'chronyd',
                'enabled': False,
                'synched': False
            }


def dns_check(test_pass=True):
    if test_pass:
        return {
            'test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'},
            '*.test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'}
        }
    else:
        return {
            'test.tld.com': {'ip_addr': None, 'status': 'FAIL'},
            '*.test.tld.com': {'ip_addr': None, 'status': 'FAIL'}
        }
