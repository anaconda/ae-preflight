
"""
Default sets of variables for reporting and the profile to check, and ensure
are setup, running, or setup to be working on the system.
"""

OS_VALUES = {
    'rhel': {
        'versions': ['7.2', '7.3', '7.4', '7.5', '7.6', '7.7', '7.8'],
    },
    'debian': {
        'versions': ['16.04'],
    },
    'suse': {
        'versions': ['12 SP2', '12 SP3'],
    }
}

DEFAULT_MODULES = [
    'iptable_filter',
    'br_netfilter',
    'iptable_nat',
    'ebtables',
    'overlay'
]

TIME_SERVICES = {
    'services': [
        'ntpd',
        'chronyd',
        'systemd-timesyncd'
    ],
    'ntpd': {
        'check': ['which', 'ntpd'],
        'names': ['ntp', 'ntpd']
    },
    'chronyd': {
        'check': ['which', 'chronyc']
    },
    'systemd-timesyncd': {
        'check': ['ls', '/lib/systemd/systemd-timesyncd']
    }
}

MODULE_EXCEPTIONS = {
    'rhel': {
        '7.2': [
            'iptable_filter',
            'iptable_nat',
            'ebtables',
            'bridge'
        ]
    },
    'centos': {
        '7.2': [
            'iptable_filter',
            'iptable_nat',
            'ebtables',
            'overlay',
            'bridge'
        ]
    }
}

DEFAULT_SYSCTL = {
    'settings': [
        'net.bridge.bridge-nf-call-ip6tables',
        'net.bridge.bridge-nf-call-iptables',
        'fs.inotify.max_user_watches',
        'fs.may_detach_mounts',
        'net.ipv4.ip_forward'
    ],
    'net.bridge.bridge-nf-call-ip6tables': '1',
    'net.bridge.bridge-nf-call-iptables': '1',
    'fs.inotify.max_user_watches': '1048576',
    'fs.may_detach_mounts': '1',
    'net.ipv4.ip_forward': '1'
}

OPEN_PORTS = [80, 443, 32009, 61009, 65535]

FILE_TYPES = ['xfs', 'ext4']

RUNNING_AGENTS = [
    'salt',
    'chef',
    'puppet',
    'redcloak',
    'cylancesvc',
    'sisidsdaemon',
    'sisipsdaemon',
    'sisipsutildaemon'
]

DIR_PATHS = [
    '/etc/chef',
    '/etc/salt',
    '/etc/puppet',
    '/etc/ansible',
    '/var/cfengine',
    '/opt/symantec',
    '/var/lib/puppet',
    '/usr/local/etc/salt',
    '/var/opt/secureworks'
]
