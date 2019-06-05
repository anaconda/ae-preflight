
from ae_preflight import defaults
from ae_preflight import report


from contextlib import closing
from subprocess import Popen
from subprocess import PIPE


import argparse
import socket
import psutil
import sys
import os
import re


"""
In python 3.8 platform is being removed and distro will be in its own package
"""
if sys.version_info[:2] <= (3, 7):
    import platform


# Try to import distro but it is only needed in python 3.8 and above
try:
    import distro
except Exception:
    pass


def execute_command(command, verbose):
    """
    Generic function to handle executing commands on the system
    """
    if verbose:
        print('Executing command: "{0}"'.format(' '.join(command)))

    p = Popen(command, stdout=PIPE, stderr=PIPE, stdin=PIPE)
    out, err = p.communicate()
    if p.returncode != 0 and verbose:
        print(
            'Error executing command "{0}" : Error {1}'.format(
                ' '.join(command),
                err.decode('utf-8')
            )
        )

    return out


def check_for_socket(interface, port, verbose):
    port_status = None
    if verbose:
        print('Checking {0} port on interface {1}'.format(port, interface))

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        # Set timeout so things do not hang if closed
        sock.settimeout(2)
        if sock.connect_ex((interface, port)) == 0:
            port_status = 'open'
        else:
            port_status = 'closed'

    return port_status


def get_active_interfaces(devices_file):
    interfaces = []
    skip_interfaces = ['veth', 'flannel', 'docker', 'lo']
    with open(devices_file) as f:
        temp = f.readline()
        while temp:
            # Run regex search to grab interface name
            search = re.search(r'^(.+?):', temp)
            if search:
                # Set the interface to a temp variable
                temp_interface = search.group(1).strip()

                # Test for inclusion to skipped interfaces
                test_interfaces = [
                    x in temp_interface for x in skip_interfaces
                ]

                # Make sure everything is False as it means valid interface
                if True not in test_interfaces:
                    interfaces.append(temp_interface)

            temp = f.readline()

    return interfaces


def get_interface_ip_address(interface, verbose):
    # Run ip addr command on host to get the interface data
    temp_info = execute_command(['ip', 'addr', 'show', interface], verbose)

    # Decode the info and get out the IP address
    if type(temp_info) == bytes:
        temp_info = temp_info.decode('utf-8')

    ip_address = None
    temp_inet = temp_info.split('inet ')
    if len(temp_inet) > 1:
        temp_cidr = temp_inet[1].split('/')

        if len(temp_cidr) > 0:
            ip_address = temp_cidr[0]

    # ip_address = temp_info.split('inet ')[1].split('/')[0]
    return ip_address


def get_os_info(verbose):
    """
    Get operating system details about the system the script is being run on.
    This will setup future steps and dictate what else needs to be done or
    checked to ensure a smooth install
    """
    profile = {}
    if verbose:
        print('Gathering OS and distribution information')

    # Ensure to use distro when running python 3.8
    if sys.version_info[:2] > (3, 7):
        linux_info = distro.distro_release_info()
        # On SUSE distro_release_info gives an empty {}
        # so get the info another way
        if linux_info == {}:
            linux_info = distro.os_release_info()

        version = 'UNK'
        if linux_info.get('version_id'):
            temp_version = linux_info.get('version_id').split('.')
            if len(temp_version) > 1:
                version = '{0}.{1}'.format(temp_version[0], temp_version[1])
            else:
                version = temp_version[0]

        profile['distribution'] = linux_info.get('id')
    else:
        temp_info = platform.linux_distribution()
        distribution = None
        if temp_info[0] != '':
            split_os = temp_info[0].split(' ')
            distribution = split_os[0].lower()

        profile['distribution'] = distribution
        linux_info = {
            'name': temp_info[0]
        }

        # Because of how platform works have to read /etc/lsb-release and get
        # info from it as well to ensure we have the right info
        if linux_info.get('name') == 'debian':
            lsb_content = None
            with open('/etc/lsb-release') as f:
                lsb_content = f.read()

            # Grab the data from lsb-release content
            if lsb_content:
                linux_info['version_id'] = (
                    re.search('DISTRIB_RELEASE=(.+?)\n', lsb_content).group(1)
                )
                distribution = (
                    re.search('DISTRIB_ID=(.+?)\n', lsb_content).group(1)
                )

            # Reset distribution from lsb-release file
            if distribution:
                profile['distribution'] = distribution.lower()

            # Manually set the name
            linux_info['name'] = 'Ubuntu'
        else:
            linux_info['version_id'] = temp_info[1]

        version = 'UNK'
        if linux_info.get('version_id'):
            temp_version = linux_info.get('version_id').split('.')
            if len(temp_version) > 1:
                version = '{0}.{1}'.format(temp_version[0], temp_version[1])
            else:
                version = temp_version[0]

    profile['version'] = version
    profile['dist_name'] = linux_info.get('name')

    based_on = None
    if os.path.isfile('/etc/redhat-release'):
        based_on = 'rhel'
    elif os.path.isfile('/etc/debian_version'):
        based_on = 'debian'
    elif os.path.isfile('/etc/os-release'):
        based_on = 'suse'

    profile['based_on'] = based_on
    return profile


def system_requirements(verbose):
    """
    Grab the memory and CPUs for the sytem to verify things are good
    """
    requirements = {
        'memory': {
            'minimum': 16.0
        },
        'cpu_cores': {
            'minimum': 8
        }
    }
    if verbose:
        print('Gathering memory and CPU information')

    temp_memory = (
        execute_command(["cat", "/proc/meminfo"], verbose)
    ).decode('utf-8')
    if temp_memory not in [None, '']:
        found = re.search(r'^MemTotal:\s+(\d+)', temp_memory)
        if found:
            temp_memory = (int(found.groups()[0])/1024.0**2)

        requirements['memory']['actual'] = round(temp_memory, 2)

    temp_cores = execute_command(["getconf", "_NPROCESSORS_ONLN"], verbose)
    if temp_cores is not None:
        requirements['cpu_cores']['actual'] = int(temp_cores.strip())

    return requirements


def mounts_check(verbose):
    """
    Checking mount points to ensure that there is enough space for everything
    /
    /tmp
    /var/lib
    /var/lib/gravity
    /opt
    /opt/anaconda
    """
    found_mounts = {}
    if verbose:
        print('Gather mount and space requirements for each mount')

    for mount in psutil.disk_partitions():
        if (
            '/var' in mount.mountpoint or
            '/opt' in mount.mountpoint or
            '/tmp' in mount.mountpoint or
            mount.mountpoint == '/'
        ):
            found_mounts[mount.mountpoint] = {
                'options': mount.opts,
                'file_system': mount.fstype
            }

    mounts = {}
    for mountpoint, mount_data in found_mounts.items():
        mounts[mountpoint] = {}
        temp_usage = psutil.disk_usage(mountpoint)
        mounts[mountpoint]['free'] = round((temp_usage.free / 1024.0**3), 2)
        mounts[mountpoint]['total'] = round((temp_usage.total / 1024.0**3), 2)
        mounts[mountpoint]['mount_options'] = mount_data.get('options')
        mounts[mountpoint]['file_system'] = mount_data.get('file_system')
        if '/tmp' in mountpoint:
            mounts[mountpoint]['recommended'] = 30.0
        elif '/var' in mountpoint:
            mounts[mountpoint]['recommended'] = 200.0
        elif '/opt' in mountpoint:
            mounts[mountpoint]['recommended'] = 100.0

        if mount_data.get('file_system') == 'xfs':
            mount_info = None
            try:
                mount_info = execute_command(['xfs_info', mountpoint], verbose)
            except Exception:
                # Just because xfs is the formatted filesystem does
                # not mean xfs_info is on the system
                pass

            if mount_info:
                ftype_test = re.search(
                    r'ftype=(\d)',
                    mount_info.decode('utf-8')
                )
                if ftype_test:
                    mounts[mountpoint]['ftype'] = ftype_test.group(1)
                else:
                    mounts[mountpoint]['ftype'] = 'UNK'
            else:
                mounts[mountpoint]['ftype'] = 'UNK'

    # Update root requirement
    root_total = 332.0
    for mount, _ in found_mounts.items():
        if '/tmp' in mount:
            root_total -= 30.0

        if '/var' in mount:
            root_total -= 200.0

        if '/opt' in mount:
            root_total -= 100.0

    mounts['/']['recommended'] = root_total
    return mounts


def check_modules(distro, version, verbose):
    """
    Check for modules and ensure things are enabled
    """
    modules = defaults.DEFAULT_MODULES
    if verbose:
        print('Checking for enabled modules based on distro and version')

    if (
        defaults.MODULE_EXCEPTIONS.get(distro) and
        defaults.MODULE_EXCEPTIONS.get(distro).get(version)
    ):
        modules = defaults.MODULE_EXCEPTIONS.get(distro).get(version)

    missing = []
    enabled = []
    lsmod_result = execute_command(['lsmod'], verbose)
    for module in modules:
        search_for = module
        if type(lsmod_result) == bytes:
            search_for = module.encode('utf-8')

        temp_result = re.search(search_for, lsmod_result)
        if temp_result:
            enabled.append(module)
        else:
            missing.append(module)

    all_modules = {
        'missing': missing,
        'enabled': enabled
    }

    return all_modules


def check_system_type(based_on, version, verbose):
    supported = {'OS': 'FAIL', 'version': 'FAIL'}
    if verbose:
        print('Checking OS compatability')

    if defaults.OS_VALUES.get(based_on):
        supported['OS'] = 'PASS'
        if version in defaults.OS_VALUES.get(based_on).get('versions'):
            supported['version'] = 'PASS'

    return supported


def selinux(selinux_config, verbose):
    """
    Check selinux and make sure it is in a good state
    """
    if verbose:
        print('Checking selinux status and configuration')

    value = execute_command(['getenforce'], verbose)
    config_option = 'disabled'
    with open(selinux_config) as f:
        temp = f.readline()
        while temp:
            search = re.search(r'^SELINUX=(.*)$', temp)
            if search:
                config_option = search.group(1)
                break
            else:
                temp = f.readline()

    status = {
        'getenforce': value.decode('utf-8').strip().lower(),
        'config': config_option.lower()
    }
    return status


def check_for_agents(verbose):
    """
    Check for config management and if it is going to get in the way
    """
    all_pids = psutil.pids()
    found_agents = []
    if verbose:
        print('Checking for agents running on system')

    for pid in all_pids:
        try:
            temp_process = psutil.Process(pid)
            for agent in defaults.RUNNING_AGENTS:
                if (
                    agent in temp_process.name().lower() and
                    temp_process.name() not in found_agents
                ):
                    found_agents.append(temp_process.name())
                    break

        except Exception:
            # Pids can be gone after gathering them all due to short
            # lived processes. Catching those and moving to the next pid
            pass

    agent_results = {'running': found_agents}
    return agent_results


def inspect_resolv_conf(resolv_conf_location, verbose):
    """
    Ensure that resolv.conf does not have anything that might interfere
    with kubernetes
    """
    all_options = []
    search_domains = []
    if verbose:
        print('Checking {0}'.format(resolv_conf_location))

    with open(resolv_conf_location) as f:
        temp = f.readline()
        while temp:
            domains = re.search(r'^search\s(.*)$', temp)
            options = re.search(r'^options\s(.*)$', temp)
            if domains:
                search_domains = domains.group(1).split(' ')

            if options:
                all_options.append(options.group(1))

            temp = f.readline()

    status = {
        'search_domains': search_domains,
        'options': all_options
    }
    return status


def check_open_ports(interface, verbose):
    open_ports = {}
    if interface:
        interfaces = [interface]
        if verbose:
            print('Checking ports on interface {0}'.format(interface))
    else:
        if verbose:
            print('Checking ports on all active interfaces')

        try:
            interfaces = get_active_interfaces('/proc/net/dev')
        except Exception:
            interfaces = []

    for interface in interfaces:
        ip_address = get_interface_ip_address(interface, verbose)
        if ip_address:
            open_ports[interface] = {}
            for port in defaults.OPEN_PORTS:
                open_ports[interface][str(port)] = (
                    check_for_socket(ip_address, port, verbose)
                )
        else:
            open_ports[interface] = 'No IP address assigned'

    return open_ports


def suse_infinity_check(system_file, verbose):
    infinity_set = False
    if verbose:
        print('Checking setting for Suse Linux in {0}'.format(system_file))

    with open(system_file) as f:
        temp = f.readline()
        while temp:
            infinity_check = re.search(r'^DefaultTasksMax=infinity', temp)
            if infinity_check:
                infinity_set = True
                break

            temp = f.readline()

    return infinity_set


def check_sysctl(verbose):
    enabled = []
    disabled = []
    incorrect = {}
    skipped = []
    if verbose:
        print('Checking sysctl settings on system')

    all_sysctl_settings = execute_command(
        ['sysctl', '-a'],
        verbose
    ).decode('utf-8')
    for setting in defaults.DEFAULT_SYSCTL.get('settings'):
        if re.search(setting, all_sysctl_settings):
            temp_result = execute_command(
                ['sysctl', setting],
                verbose
            ).decode('utf-8')
            if temp_result:
                result = temp_result.split('=')[1].strip()
                if str(result) == defaults.DEFAULT_SYSCTL.get(setting):
                    enabled.append(setting)
                elif defaults.DEFAULT_SYSCTL.get(setting) not in ['1', '0']:
                    incorrect[setting] = result
                else:
                    disabled.append(setting)
            else:
                disabled.append(setting)
        else:
            skipped.append(setting)

    sysctl_modules = {
        'enabled': enabled,
        'disabled': disabled,
        'skipped': skipped,
        'incorrect': incorrect
    }
    return sysctl_modules


def check_dir_paths(verbose):
    dir_paths = []
    if verbose:
        print('Checking for directories on system')

    for dir in defaults.DIR_PATHS:
        if os.path.exists(dir):
            dir_paths.append(dir)

    return dir_paths


def check_for_ntp_synch(verbose):
    ntp_info = {
        'using': None,
        'installed': False,
        'enabled': False,
        'synched': False
    }
    if verbose:
        print('Checking NTP setup and configuration on system')

    for service in defaults.TIME_SERVICES.get('services'):
        check_for_service = execute_command(
            defaults.TIME_SERVICES.get(service).get('check'),
            verbose
        ).decode('utf-8')
        if check_for_service not in ['', None]:
            ntp_info['installed'] = True
            names = defaults.TIME_SERVICES.get(service).get('names')
            if names is None:
                names = [service]

            temp_status = None
            for name in names:
                service_status = execute_command(
                    ['systemctl', 'status', name],
                    verbose
                ).decode('utf-8')
                temp_status = re.search(
                    r'Active\:\sactive\s\(running\)',
                    service_status
                )
                if temp_status:
                    break

            if temp_status:
                ntp_info['using'] = service
            else:
                ntp_info['installed'] = service

            break

    # If ntpd or chronyd is installed and running
    if ntp_info.get('installed'):
        timedatectl_status = execute_command(
            ['timedatectl', 'status'],
            verbose
        ).decode('utf-8')

        enabled_status = 'no'
        if ntp_info['using'] == 'systemd-timesyncd':
            temp_enabled = re.search(
                r'Network time on\:\s(.+?)\s+',
                timedatectl_status
            )
        else:
            temp_enabled = re.search(
                r'NTP enabled\:\s(.+?)\s+',
                timedatectl_status
            )

        if temp_enabled:
            enabled_status = temp_enabled.group(1).strip().lower()
            if enabled_status == 'yes':
                ntp_info['enabled'] = True

        synched_status = 'no'
        temp_synched = re.search(
            r'NTP synchronized\:\s(.+?)\s+',
            timedatectl_status
        )
        if temp_synched:
            synched_status = temp_synched.group(1).strip().lower()
            if synched_status == 'yes':
                ntp_info['synched'] = True

    return ntp_info


def check_dns_resolution(verbose, hostname):
    dns_info = {}
    if verbose:
        print('Checking for DNS resolution')

    tld = None
    wildcard = None
    check_wildcard = re.search(r'^(\*\.)(.*)', hostname)
    if check_wildcard:
        tld = check_wildcard.group(2)
        wildcard = hostname
    else:
        tld = hostname
        wildcard = '*.{0}'.format(hostname)

    test_wildcard = 'test.{0}'.format(tld)
    temp_checks = [tld, test_wildcard]
    for i in range(0, 2):
        if i == 1:
            domain_key = wildcard
        else:
            domain_key = tld

        dns_info[domain_key] = {'ip_addr': None, 'status': 'FAIL'}
        temp_ip = None
        try:
            temp_ip = socket.gethostbyname(temp_checks[i])
        except Exception:
            # No need to do anything if DNS does not resolve
            pass

        if temp_ip:
            dns_info[domain_key]['ip_addr'] = temp_ip
            dns_info[domain_key]['status'] = 'PASS'

    return dns_info


def handle_arguments():
    description = (
        'System checks and tests to ensure system meets the installation '
        'requirements defined here: https://enterprise-docs.anaconda.com/e'
        'n/latest/install/reqs.html'
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        '-i',
        '--interface',
        required=False,
        help=(
            'Specify interface name i.e. eth0 to test instead '
            'of checking all interfaces'
        )
    )
    parser.add_argument(
        '--hostname',
        required=False,
        help=(
            'Hostname being used for AE5. DNS resolution will be tested '
            'for the specified doamin and corresponding wildcard domain.'
        )
    )
    parser.add_argument(
        '-v',
        '--verbose',
        required=False,
        action='count',
        help='Enable verbosity'
    )
    args = parser.parse_args()
    return args


def main():
    """
    Run each of the functions and store the results to be reported on in a
    results file
    """
    system_info = {}
    args = handle_arguments()

    system_info['profile'] = get_os_info(args.verbose)
    system_info['compatability'] = check_system_type(
        system_info.get('profile').get('based_on'),
        system_info.get('profile').get('version'),
        args.verbose
    )
    system_info['resources'] = system_requirements(args.verbose)
    system_info['mounts'] = mounts_check(args.verbose)
    system_info['resolv'] = inspect_resolv_conf(
        '/etc/resolv.conf',
        args.verbose
    )
    system_info['ports'] = check_open_ports(args.interface, args.verbose)
    system_info['agents'] = check_for_agents(args.verbose)
    system_info['modules'] = check_modules(
        system_info.get('profile').get('distribution'),
        system_info.get('profile').get('version'),
        args.verbose
    )

    system_info['selinux'] = None
    if system_info.get('profile').get('based_on').lower() == 'rhel':
        system_info['selinux'] = selinux('/etc/selinux/config', args.verbose)

    system_info['infinity_set'] = None
    if system_info.get('profile').get('distribution').lower() == 'sles':
        system_info['infinity_set'] = suse_infinity_check(
            '/etc/systemd/system.conf',
            args.verbose
        )

    system_info['sysctl'] = check_sysctl(args.verbose)
    system_info['dir_paths'] = check_dir_paths(args.verbose)
    system_info['ntp'] = check_for_ntp_synch(args.verbose)

    if args.hostname:
        system_info['dns'] = check_dns_resolution(args.verbose, args.hostname)

    overall_result = report.process_results(system_info)
    print('\nOverall Result: {0}'.format(overall_result))
    print(
        'To view details about the results a results.txt file has been '
        'generated in the current directory\n'
    )


if __name__ == '__main__':
    main()
