from contextlib import closing
from subprocess import Popen
from subprocess import PIPE


import argparse
import socket
import psutil
import distro
import os
import re


OS_VALUES = {
    'rhel': {
        'versions': ['7.2', '7.3', '7.4', '7.5'],
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
DEFAULT_SYSCTL = [
    'net.bridge.bridge-nf-call-ip6tables',
    'net.bridge.bridge-nf-call-iptables',
    'fs.may_detach_mounts',
    'net.ipv4.ip_forward'
]
OPEN_PORTS = [80, 443, 32009, 61009, 65535]
FILE_TYPES = ['xfs', 'ext4']
RUNNING_AGENTS = [
    'salt',
    'puppet',
    'sisidsdaemon',
    'sisipsdaemon',
    'sisipsutildaemon'
]


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

    ip_address = temp_info.split('inet ')[1].split('/')[0]
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

    linux_info = distro.distro_release_info()
    # On SUSE distro_release_info gives an empty {} so get the info another way
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
    )
    if temp_memory is not None:
        found = re.search(r'^MemTotal:\s+(\d+)', temp_memory.decode('utf-8'))
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
            mounts[mountpoint]['recommended'] = 100.0
        elif '/opt' in mountpoint:
            mounts[mountpoint]['recommended'] = 100.0

        if mount_data.get('file_system') == 'xfs':
            mount_info = execute_command(['xfs_info', mountpoint], verbose)
            ftype_test = re.search(r'ftype=(\d)', mount_info.decode('utf-8'))
            if ftype_test:
                mounts[mountpoint]['ftype'] = ftype_test.group(1)
            else:
                mounts[mountpoint]['ftype'] = 'UNK'

    # Update root requirement
    root_total = 230.0
    for mount, _ in found_mounts.items():
        if '/tmp' in mount:
            root_total -= 30.0

        if '/var' in mount:
            root_total -= 100.0

        if '/opt' in mount:
            root_total -= 100.0

    mounts['/']['recommended'] = root_total
    return mounts


def check_modules(distro, version, verbose):
    """
    Check for modules and ensure things are enabled
    """
    modules = DEFAULT_MODULES
    if verbose:
        print('Checking for enabled modules based on distro and version')

    if (
        MODULE_EXCEPTIONS.get(distro) and
        MODULE_EXCEPTIONS.get(distro).get(version)
    ):
        modules = MODULE_EXCEPTIONS.get(distro).get(version)

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

    if OS_VALUES.get(based_on):
        supported['OS'] = 'PASS'
        if version in OS_VALUES.get(based_on).get('versions'):
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
            for agent in RUNNING_AGENTS:
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

        interfaces = get_active_interfaces('/proc/net/dev')

    for interface in interfaces:
        ip_address = get_interface_ip_address(interface, verbose)
        open_ports[interface] = {}
        for port in OPEN_PORTS:
            open_ports[interface][str(port)] = (
                check_for_socket(ip_address, port, verbose)
            )

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
    if verbose:
        print('Checking sysctl settings on system')

    for setting in DEFAULT_SYSCTL:
        temp_result = execute_command(
            ['sysctl', setting],
            verbose
        ).decode('utf-8')
        if temp_result:
            result = temp_result.split('=')[1].strip()
            if str(result) == '1':
                enabled.append(setting)
            else:
                disabled.append(setting)
        else:
            disabled.append(setting)

    sysctl_modules = {'enabled': enabled, 'disabled': disabled}
    return sysctl_modules


def process_results(system_info):
    """
    Layout the report file and print out an overall pass/warn/fail for each
    section that was checked
    """
    overall_result = 'PASS'
    with open('results.txt', 'w+') as f:
        f.write('=========================================================\n')
        f.write('                SYSTEM PROFILE RESULTS                   \n')
        f.write('=========================================================\n')

        # Compatability and basic system info
        profile = system_info['profile']
        f.write('\nOS Information\n')
        f.write('Name:     {0}\n'.format(profile.get('distribution').title()))
        f.write('Version:  {0}\n'.format(profile.get('version')))
        f.write('Based On: {0}\n\n'.format(profile.get('based_on')))
        f.write('---------------------------------------------------------\n')

        compatability = system_info['compatability']
        f.write('\nCompatability\n')
        f.write('Supported OS:      {0}\n'.format(compatability['OS']))
        f.write('Supported Version: {0}\n\n'.format(compatability['version']))
        if compatability['OS'] == 'FAIL' or compatability['version'] == 'FAIL':
            overall_result = 'FAIL'

        f.write('---------------------------------------------------------\n')

        resources = system_info['resources']
        memory = resources.get('memory')
        f.write('\nMemory\n')
        f.write('Minimum: {0}\n'.format(memory.get('minimum')))
        f.write('Actual:  {0}\n'.format(memory.get('actual')))
        memory_result = 'FAIL'
        if memory.get('actual') >= memory.get('minimum'):
            memory_result = 'PASS'

        f.write('Memory:  {0}\n\n'.format(memory_result))
        if memory_result == 'FAIL':
            overall_result = 'FAIL'

        f.write('---------------------------------------------------------\n')

        # Cores
        cores = resources.get('cpu_cores')
        core_result = 'FAIL'
        f.write('\nCPU Cores\n')
        f.write('Minimum:  {0}\n'.format(cores.get('minimum')))
        f.write('Actual:   {0}\n'.format(cores.get('actual')))
        if cores.get('actual') >= cores.get('minimum'):
            core_result = 'PASS'

        f.write('CPU Core: {0}\n\n'.format(core_result))
        if core_result == 'FAIL':
            overall_result = 'FAIL'

        f.write('---------------------------------------------------------\n')

        # Mounts
        mounts = system_info['mounts']
        f.write('\nMounts\n')
        overall_mount_result = 'WARN'
        ftype_incorrect = False
        for mount, mount_data in mounts.items():
            mount_result = 'WARN'
            f.write('Mount Point:  {0}\n'.format(mount))
            f.write(
                'Recommended:  {0} GB\n'.format(
                    mount_data.get('recommended')
                )
            )
            f.write(
                'Total:        {0} GB\n'.format(mount_data.get('total'))
            )

            f.write(
                'Free:         {0} GB\n'.format(mount_data.get('free'))
            )
            f.write(
                'File System:  {0}\n'.format(
                    mount_data.get('file_system')
                )
            )
            if mount_data.get('file_system') == 'xfs':
                f.write(
                    'Ftype:        {0}\n'.format(mount_data.get('ftype'))
                )

            # Check to ensure the free space and file system pass
            if (
                mount_data.get('free') >= mount_data.get('recommended') and
                mount_data.get('file_system') in FILE_TYPES
            ):
                # Check for xfs and if not then pass
                if mount_data.get('file_system') == 'xfs':
                    # Ensure that the ftype was set correctly
                    if mount_data.get('ftype') == '1':
                        mount_result = 'PASS'
                    else:
                        ftype_incorrect = True
                else:
                    mount_result = 'PASS'

            f.write('Mount Result: {0}\n\n'.format(mount_result))
            overall_mount_result = mount_result

        if overall_mount_result == 'WARN':
            f.write(
                'Note: The free space may have fallen below specific size '
                'requirements due to reserve space and/or small files placed '
                'on the mount after formatting. Confirm that the size is '
                'close to the requested size before proceeding.\n\n'
            )
            if ftype_incorrect:
                f.write(
                    'Note: XFS file system should be formatted with the '
                    'option ftype=1 in order to support the overlay driver '
                    ' for docker. In order to fix the issue the file system '
                    'will need to be recreated and can be done using the '
                    'following example:\nmkfs.xfs -n ftype=1 '
                    '/path/to/your/device\n\n'
                )

        if overall_result == 'PASS' and overall_mount_result == 'WARN':
            overall_result = 'WARN'

        f.write('---------------------------------------------------------\n')

        # Selinux
        if system_info.get('profile').get('based_on').lower() == 'rhel':
            selinux = system_info['selinux']
            selinux_result = 'FAIL'
            f.write('\nSelinux Status\n')
            f.write(
                'Current Status: {0}\n'.format(
                    selinux.get('getenforce').title()
                )
            )
            f.write(
                'Config Setting: {0}\n'.format(selinux.get('config').title())
            )

            if (
                selinux.get('config').lower() != 'enforcing' and
                selinux.get('getenforce').lower() != 'enforcing'
            ):
                selinux_result = 'PASS'

            f.write('Selinux Result: {0}\n\n'.format(selinux_result))
            if selinux_result == 'FAIL':
                overall_result = 'FAIL'
        else:
            f.write('\nSelinux Result: SKIPPED\n\n')

        f.write('---------------------------------------------------------\n')

        # /etc/resolv.conf
        resolv = system_info['resolv']
        options_result = 'PASS'
        search_domain_result = 'FAIL'
        f.write('\n/etc/resolv.conf Check\n')
        f.write(
            'Search Domains: {0}\n'.format(
                len(resolv.get('search_domains', []))
            )
        )
        if len(resolv.get('search_domains', [])) <= 3:
            search_domain_result = 'PASS'

        for option in resolv.get('options', []):
            f.write('Added Option: {0}\n'.format(option))
            if 'rotate' in option:
                f.write(
                    'WARNING: rotate option has been known to create issues '
                    'on install and is recommended to comment this out\n'
                )
                options_result = 'WARN'

        f.write('\nSearch Domain Result: {0}\n'.format(search_domain_result))
        f.write('Options Result: {0}\n\n'.format(options_result))
        if search_domain_result == 'FAIL':
            overall_result = 'FAIL'

        if overall_result == 'PASS' and options_result == 'WARN':
            overall_result = 'WARN'

        f.write('---------------------------------------------------------\n')

        # Ports
        ports = system_info['ports']
        f.write('\nPort Check\n')
        f.write(
            'Note: This test will check all interfaces for open ports and '
            'each interface may not apply to the installation\n'
        )
        for interface, interface_data in ports.items():
            interface_result = 'PASS'
            f.write('\nInterface {0}:\n'.format(interface))
            for port, port_status in interface_data.items():
                f.write(
                    'Port: {0} - {1}\n'.format(
                        port,
                        port_status.title()
                    )
                )
                if port_status == 'closed':
                    interface_result = 'WARN'

            f.write(
                '\n{0} Result: {1}\n\n'.format(
                    interface,
                    interface_result
                )
            )
            if overall_result == 'PASS' and interface_result == 'WARN':
                overall_result = 'WARN'

        f.write('---------------------------------------------------------\n')

        # Agents
        agents = system_info['agents']
        agent_result = 'PASS'
        f.write('\nAgent Checks\n')
        if len(agents.get('running', [])) > 0:
            agent_result = 'WARN'
            for agent in agents.get('running'):
                f.write('Running: {0}\n'.format(agent))

            f.write(
                'WARNING: These agents have been known to cause issues with '
                'the system as it could block traffic, or change settings '
                'that are needed by Anaconda Enterprise to function properly\n'
            )
        else:
            f.write('No running agents found\n')

        f.write('\nAgent Result: {0}\n\n'.format(agent_result))
        if overall_result == 'PASS' and agent_result == 'WARN':
            overall_result = 'WARN'

        f.write('---------------------------------------------------------\n')

        # Modules
        modules = system_info['modules']
        module_result = 'PASS'
        f.write('\nModule Checks\n')
        f.write('Enabled:\n')
        for module in modules.get('enabled', []):
            f.write('{0}\n'.format(module))

        if len(modules.get('missing', [])) > 0:
            module_result = 'FAIL'
            f.write('\nMissing:\n')
            for module in modules.get('missing'):
                f.write('{0}\n'.format(module))

            f.write(
                '\nHOW TO\nTo enable a module you can do the following as '
                'root:\nmodprobe MODULE_NAME\n\nTo persist through a reboot '
                'do the following as root:\necho -e "MODULE_NAME" > '
                '/etc/modules-load.d/MODULE_NAME.conf\n'
            )

        f.write('\nModule Result: {0}\n\n'.format(module_result))
        f.write('---------------------------------------------------------\n')

        # Suse Infinity
        if system_info.get('profile').get('distribution').lower() == 'sles':
            infinity = system_info['infinity_set']
            infinity_result = 'FAIL'
            f.write('\nInfinty Max Tasks\n')
            if infinity:
                infinity_result = 'PASS'

            f.write('Result: {0}\n\n'.format(infinity_result))
            if infinity_result == 'FAIL':
                overall_result = 'FAIL'
                f.write(
                    'HOW TO\nTo enable infinity on SUSE then add the '
                    'following to /etc/systemd/system.conf:\n'
                    'DefaultTasksMax=infinity\n\n'
                )

            f.write(
                '---------------------------------------------------------\n'
            )

        # sysctl
        sysctl = system_info['sysctl']
        sysctl_result = 'PASS'
        f.write('\nSysctl Settings\n')
        f.write('Enabled:\n')
        for setting in sysctl.get('enabled', []):
            f.write('{0}\n'.format(setting))

        if len(sysctl.get('disabled', [])) > 0:
            sysctl_result = 'FAIL'
            f.write('\nDisabled:\n')
            for setting in sysctl.get('disabled'):
                f.write('{0}\n'.format(setting))

        f.write('\nSysctl Result: {0}\n\n'.format(sysctl_result))
        if sysctl_result == 'FAIL':
            overall_result = 'FAIL'
            f.write(
                'HOW TO\nTo enable a setting you can do the following as root:'
                '\nsysctl -w SYSCTL_SETTING=1\n\nTo persist through a reboot '
                'do the following as root:\necho -e "SYSCTL_SETTING = 1" '
                '>> /etc/sysctl.d/10-SYSCTL_SETTING.conf"\n\n'
            )

        f.write('=========================================================\n')

        f.write('\nOverall Result: {0}\n\n'.format(overall_result))

        f.write('=========================================================\n')

    return overall_result


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

    if system_info.get('profile').get('based_on').lower() == 'rhel':
        system_info['selinux'] = selinux('/etc/selinux/config', args.verbose)

    system_info['infinity_set'] = None
    if system_info.get('profile').get('distribution').lower() == 'sles':
        system_info['infinity_set'] = suse_infinity_check(
            '/etc/systemd/system.conf',
            args.verbose
        )

    system_info['sysctl'] = check_sysctl(args.verbose)
    overall_result = process_results(system_info)
    print('\nOverall Result: {0}'.format(overall_result))
    print(
        'To view details about the results a results.txt file has been '
        'generated in the current directory\n'
    )


if __name__ == '__main__':
    main()
