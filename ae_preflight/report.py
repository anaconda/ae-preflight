
from ae_preflight import defaults


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
                'Minimum Size: {0} GB\n'.format(
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
                mount_data.get('file_system') in defaults.FILE_TYPES
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
            if isinstance(interface_data, dict):
                for port, port_status in interface_data.items():
                    f.write(
                        'Port: {0} - {1}\n'.format(
                            port,
                            port_status.title()
                        )
                    )
                    if port_status == 'closed':
                        interface_result = 'WARN'
            else:
                f.write('Interface has no assigned IP address\n')
                interface_result = 'WARN'

            f.write(
                '\n{0} Result: {1}\n'.format(
                    interface,
                    interface_result
                )
            )
            if overall_result == 'PASS' and interface_result == 'WARN':
                overall_result = 'WARN'

        f.write(
            '\n---------------------------------------------------------\n'
        )

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
        module_commands = []
        for module in modules.get('enabled', []):
            f.write('{0}\n'.format(module))

        if len(modules.get('missing', [])) > 0:
            module_result = 'FAIL'
            f.write('\nMissing:\n')
            for module in modules.get('missing'):
                f.write('{0}\n'.format(module))
                module_commands.append(
                    'echo -e "{0}" > /etc/modules-load.d/{0}.conf'.format(
                        module
                    )
                )

            f.write(
                '\nHOW TO\nTo enable a module you can do the following as '
                'root:\nmodprobe MODULE_NAME\n\nTo persist through a reboot '
                'do the following as root:\necho -e "MODULE_NAME" > '
                '/etc/modules-load.d/MODULE_NAME.conf\n'
            )
            f.write(
                '\nCOMMANDS\nYou can use the following commands to enable the '
                'appropriate modules that are required.\n'
            )
            for command in module_commands:
                f.write('{0}\n'.format(command))

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
        f.write('Enabled/Correct:\n')
        sysctl_commands = []

        for setting in sysctl.get('enabled', []):
            f.write('{0}\n'.format(setting))

        if len(sysctl.get('incorrect', {})) > 0:
            sysctl_result = 'FAIL'
            f.write('\nIncorrect:\n')
            for setting, value in sysctl.get('incorrect').items():
                f.write('{0} = {1}\n'.format(setting, value))
                sysctl_commands.append(
                    'echo -e "{0} = {1}" >> /etc/sysctl.d/10-{0}.conf'.format(
                        setting,
                        defaults.DEFAULT_SYSCTL.get(setting)
                    )
                )

        if len(sysctl.get('disabled', [])) > 0:
            sysctl_result = 'FAIL'
            f.write('\nDisabled:\n')
            for setting in sysctl.get('disabled'):
                f.write('{0}\n'.format(setting))
                sysctl_commands.append(
                    'echo -e "{0} = 1" >> /etc/sysctl.d/10-{0}.conf'.format(
                        setting
                    )
                )

        if len(sysctl.get('skipped', [])) > 0:
            f.write('\nSkipped:\n')
            for setting in sysctl.get('skipped'):
                f.write('{0}\n'.format(setting))

        if sysctl_result == 'FAIL':
            overall_result = 'FAIL'
            f.write(
                'HOW TO\nTo enable a setting you can do the following as root:'
                '\nsysctl -w SYSCTL_SETTING=1\n\nTo persist through a reboot '
                'do the following as root:\necho -e "SYSCTL_SETTING = 1" '
                '>> /etc/sysctl.d/10-SYSCTL_SETTING.conf"\n\n'
            )

            f.write(
                'COMMANDS\nYou can use the following commands to enable the '
                'appropriate settings that are required.\n'
            )
            for command in sysctl_commands:
                f.write('{0}\n'.format(command))

        f.write('\nSysctl Result: {0}\n\n'.format(sysctl_result))

        f.write('---------------------------------------------------------\n')

        # dir paths
        dir_paths = system_info['dir_paths']
        path_result = 'PASS'
        f.write('\nDirectory Checks\n')

        if len(dir_paths) > 0:
            f.write('Found directories:\n')
            path_result = 'WARN'
            for dir_path in dir_paths:
                f.write('{0}\n'.format(dir_path))
        else:
            f.write('No directories found\n')

        if path_result == 'WARN':
            f.write(
                'Note: The directory check is looking for directories '
                'created or left over from processes, config management, '
                'and other services that have been found to cause issues '
                'with AE5.\n\n'
            )

        f.write('\nDirectory Result: {0}\n\n'.format(path_result))

        f.write('---------------------------------------------------------\n')

        # dir paths
        ntp = system_info['ntp']
        ntp_result = 'PASS'
        f.write('\nNTP Checks\n')
        if ntp.get('using'):
            f.write('Using:        {0}\n'.format(ntp.get('using')))
        else:
            ntp_result = 'FAIL'
            f.write('Using:        None\n')

        f.write('Installed:    {0}\n'.format(ntp.get('installed')))
        f.write('Enabled:      {0}\n'.format(ntp.get('enabled')))
        f.write('Synchronized: {0}\n'.format(ntp.get('synched')))

        if (
            not ntp.get('installed') or
            not ntp.get('enabled') or
            not ntp.get('synched')
        ):
            ntp_result = 'FAIL'

        f.write('\nNTP Result: {0}\n\n'.format(ntp_result))

        if ntp_result == 'FAIL':
            f.write(
                'Note: NTP is vitally important to a system, and will '
                'prevent time drift among the servers in the kubernetes '
                'cluster. Time drift has been known to cause issues with '
                'etcd, and ordered events. It is advisable to install, '
                'setup, and sync all servers to a central time server.\n\n'
            )

        if system_info.get('dns'):

            f.write(
                '---------------------------------------------------------\n'
            )

            # DNS Checks
            dns = system_info['dns']
            dns_result = 'PASS'
            f.write('\nDNS Checks\n')

            for domain, data in dns.items():
                f.write('Testing domain:      {0}\n'.format(domain))
                f.write(
                    'Resolved IP address: {0}\n\n'.format(
                        data.get('ip_addr', 'None')
                    )
                )
                if dns_result != 'FAIL':
                    dns_result = data.get('status')

            f.write('DNS Result: {0}\n\n'.format(dns_result))

            if dns_result == 'FAIL':
                f.write(
                    'Note: In order for the system to function correctly '
                    'both a TLD and wildcard DNS entry are required. Both '
                    'domains would need to resolve to the AE5 master and you '
                    'can find out more information here: https://enterprise'
                    '-docs.anaconda.com/en/latest/install/reqs.html?'
                    'highlight=DNS#reqs-dns.\n\n'
                )

        f.write('=========================================================\n')

        f.write('\nOverall Result: {0}\n\n'.format(overall_result))

        f.write('=========================================================\n')

    return overall_result
