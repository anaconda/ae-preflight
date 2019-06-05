
from __future__ import absolute_import


from .fixtures import reporting_returns
from .fixtures import command_returns
from ae_preflight import profile


import ae_preflight
import subprocess
import socket
import psutil
import glob
import sys
import os


if sys.version_info[:2] >= (2, 7):
    from unittest import TestCase
else:
    from unittest2 import TestCase


try:
    from unittest import mock
except ImportError:
    import mock


class TestSystemProfile(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        files = glob.glob('results.txt')
        for item in files:
            os.remove(item)

    def test_version(self):
        self.assertEquals(
            ae_preflight.__version__,
            '0.1.6',
            'Version does not match expected value'
        )

    # Execute command
    def test_execute_command_success(self):
        test_command = ['getenforce']
        selinux_status = None
        with mock.patch('ae_preflight.profile.Popen') as popen:
            popen.return_value.communicate.return_value = ('enforcing', '')
            popen.return_value.returncode = 0
            selinux_status = profile.execute_command(test_command, False)

        self.assertEqual(
            selinux_status,
            'enforcing',
            'Status does not equal expected output'
        )

    def test_execute_command_error(self):
        test_command = ['getenforce']
        selinux_status = None
        with mock.patch('ae_preflight.profile.Popen') as popen:
            popen.return_value.communicate.return_value = ('', b'Error')
            popen.return_value.returncode = 1
            selinux_status = profile.execute_command(test_command, True)

        self.assertEqual(
            selinux_status,
            '',
            'Status does not equal expected output'
        )

    def test_execute_command_verbose_success(self):
        test_command = ['getenforce']
        selinux_status = None
        with mock.patch('ae_preflight.profile.Popen') as popen:
            popen.return_value.communicate.return_value = ('enforcing', '')
            popen.return_value.returncode = 0
            selinux_status = profile.execute_command(test_command, True)

        self.assertEqual(
            selinux_status,
            'enforcing',
            'Status does not equal expected output'
        )

    # Socket
    def test_socket_success(self):
        port_status = 'Not Tested'
        with mock.patch('ae_preflight.profile.socket') as sock:
            sock.socket.return_value.connect_ex.return_value = 0
            port_status = profile.check_for_socket('eth0', '80', True)

        self.assertEquals(
            port_status,
            'open',
            'Did not get expected value on port status'
        )

    def test_socket_failure(self):
        port_status = 'Not Tested'
        with mock.patch('ae_preflight.profile.socket') as sock:
            sock.socket.return_value.connect_ex.return_value = 1
            port_status = profile.check_for_socket('eth0', '443', False)

        self.assertEquals(
            port_status,
            'closed',
            'Did not get expected value on port status'
        )

    # Active interfaces
    def test_get_interfaces(self):
        expected_result = ['eth0']
        interfaces = profile.get_active_interfaces(
            'tests/fixtures/proc_net_dev'
        )
        self.assertEquals(
            expected_result,
            interfaces,
            'Did not get the expected results for all interfaces'
        )

    # IP address
    def test_get_ip_address_bytes(self):
        expected_result = '10.200.30.165'
        with mock.patch('ae_preflight.profile.execute_command') as cmd:
            cmd.return_value = command_returns.ip_addr_show()
            ip_address = profile.get_interface_ip_address('eth0', False)

        self.assertEquals(
            expected_result,
            ip_address,
            'Did not get the expected IP address'
        )

    def test_get_ip_address_string(self):
        expected_result = '10.200.30.165'
        with mock.patch('ae_preflight.profile.execute_command') as cmd:
            cmd.return_value = command_returns.ip_addr_show().decode('utf-8')
            ip_address = profile.get_interface_ip_address('eth0', False)

        self.assertEquals(
            expected_result,
            ip_address,
            'Did not get the expected IP address'
        )

    def test_get_ip_address_bad_interface(self):
        expected_result = None
        with mock.patch('ae_preflight.profile.execute_command') as cmd:
            cmd.return_value = (
                command_returns.ip_addr_show_no_ip().decode('utf-8')
            )
            ip_address = profile.get_interface_ip_address(
                'enP33102p0s2',
                False
            )

        self.assertEquals(
            expected_result,
            ip_address,
            'Did not get the expected IP address'
        )

    # OS Info
    def test_os_info_rhel_platform(self):
        expected_output = {
            'distribution': 'centos',
            'version': '7.5',
            'dist_name': 'CentOS Linux',
            'based_on': 'rhel'
        }
        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 7, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 7, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.platform.linux_distribution'
                ) as os:
                    os.return_value = command_returns.distro_release_info(
                        'centos'
                    )
                    with mock.patch(
                        'ae_preflight.profile.os.path.isfile'
                    ) as file:
                        file.return_value = True
                        os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_rhel_distro(self):
        expected_output = {
            'distribution': 'centos',
            'version': '7.5',
            'dist_name': 'CentOS Linux',
            'based_on': 'rhel'
        }
        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 8, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 8, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.distro.distro_release_info'
                ) as os:
                    os.return_value = command_returns.distro_release_info(
                        'centos'
                    )
                    with mock.patch(
                        'ae_preflight.profile.os.path.isfile'
                    ) as file:
                        file.return_value = True
                        os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_suse_distro(self):
        expected_output = {
            'distribution': 'sles',
            'version': '15',
            'dist_name': 'SLES',
            'based_on': 'suse'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, False, True]

        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 8, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 8, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.distro.distro_release_info'
                ) as os:
                    os.return_value = {}
                    with mock.patch(
                        'ae_preflight.profile.distro.os_release_info'
                    ) as distro:
                        distro.return_value = (
                            command_returns.distro_release_info('suse')
                        )
                        with mock.patch(
                            'ae_preflight.profile.os.path.isfile',
                            side_effect=mock_response
                        ):
                            os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_suse_platform(self):
        expected_output = {
            'distribution': 'suse',
            'version': '12',
            'dist_name': 'SUSE Linux Enterprise Server',
            'based_on': 'suse'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, False, True]

        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 7, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 7, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.platform.linux_distribution'
                ) as os:
                    os.return_value = command_returns.distro_release_info(
                        'suse'
                    )
                    with mock.patch(
                        'ae_preflight.profile.os.path.isfile',
                        side_effect=mock_response
                    ):
                        os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_debian_platform(self):
        expected_output = {
            'distribution': 'ubuntu',
            'version': '16.04',
            'dist_name': 'Ubuntu',
            'based_on': 'debian'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, True]
        lsb_return = (
            'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=16.04\n'
            'DISTRIB_CODENAME=xenial\nDISTRIB_DESCRIPTION="'
            'Ubuntu 16.04.6 LTS"\n'
        )
        mocked_open = mock.mock_open(read_data=lsb_return)

        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 7, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 7, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.platform.linux_distribution'
                ) as os:
                    os.return_value = command_returns.distro_release_info(
                        'ubuntu'
                    )
                    with mock.patch('ae_preflight.profile.open', mocked_open):
                        with mock.patch(
                            'ae_preflight.profile.os.path.isfile',
                            side_effect=mock_response
                        ):
                            os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_debian_distro(self):
        expected_output = {
            'distribution': 'ec2',
            'version': '16.04',
            'dist_name': 'Ubuntu',
            'based_on': 'debian'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, True]

        with mock.patch('tests.fixtures.command_returns.sys') as v_info:
            v_info.version_info = (3, 8, 0, 'final', 0)
            with mock.patch('ae_preflight.profile.sys') as version:
                version.version_info = (3, 8, 0, 'final', 0)
                with mock.patch(
                    'ae_preflight.profile.distro.distro_release_info'
                ) as os:
                    os.return_value = command_returns.distro_release_info(
                        'ubuntu'
                    )
                    with mock.patch(
                        'ae_preflight.profile.os.path.isfile',
                        side_effect=mock_response
                    ):
                        os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    # Memory and CPU
    def test_cpu_memory_gets(self):
        expected_value = {
            'memory': {
                'minimum': 16.0,
                'actual': 251.88
            },
            'cpu_cores': {
                'minimum': 8,
                'actual': 64
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.proc_meminfo(),
            command_returns.getconf_nproc()
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            results = profile.system_requirements(True)

        self.assertEquals(
            expected_value,
            results,
            'Returned results do not match expected results'
        )

    # Disk space
    def test_disk_space(self):
        expected_output = {
            '/': {
                'recommended': 2.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'xfs',
                'ftype': '1'
            },
            '/tmp': {
                'recommended': 30.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/opt/anaconda': {
                'recommended': 100.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/var': {
                'recommended': 200.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
        ]
        with mock.patch(
            'ae_preflight.profile.psutil.disk_partitions'
        ) as part:
            part.return_value = command_returns.psutil_disk_partitions()
            with mock.patch(
                'ae_preflight.profile.psutil.disk_usage',
                side_effect=mock_response
            ):
                with mock.patch(
                    'ae_preflight.profile.execute_command'
                ) as command:
                    command.return_value = command_returns.xfs_info()
                    returns = profile.mounts_check(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returns do not match expected result'
        )

    def test_disk_space_unkown_ftype(self):
        expected_output = {
            '/': {
                'recommended': 2.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'xfs',
                'ftype': 'UNK'
            },
            '/tmp': {
                'recommended': 30.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/opt/anaconda': {
                'recommended': 100.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/var': {
                'recommended': 200.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
        ]
        with mock.patch(
            'ae_preflight.profile.psutil.disk_partitions'
        ) as part:
            part.return_value = command_returns.psutil_disk_partitions()
            with mock.patch(
                'ae_preflight.profile.psutil.disk_usage',
                side_effect=mock_response
            ):
                with mock.patch(
                    'ae_preflight.profile.execute_command'
                ) as command:
                    command.return_value = b'This is a test return'
                    returns = profile.mounts_check(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returns do not match expected result'
        )

    def test_disk_space_unkown_ftype_exceptions(self):
        expected_output = {
            '/': {
                'recommended': 2.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'xfs',
                'ftype': 'UNK'
            },
            '/tmp': {
                'recommended': 30.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/opt/anaconda': {
                'recommended': 100.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            },
            '/var': {
                'recommended': 200.0,
                'free': 198.13,
                'total': 199.7,
                'mount_options': 'rw,inode64,noquota',
                'file_system': 'ext4'
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
            command_returns.psutil_disk_usage(),
        ]

        raise_exception = mock.Mock()
        raise_exception.side_effect = subprocess.CalledProcessError
        with mock.patch(
            'ae_preflight.profile.psutil.disk_partitions'
        ) as part:
            part.return_value = command_returns.psutil_disk_partitions()
            with mock.patch(
                'ae_preflight.profile.psutil.disk_usage',
                side_effect=mock_response
            ):
                with mock.patch(
                    'ae_preflight.profile.execute_command',
                    side_effect=raise_exception
                ):
                    returns = profile.mounts_check(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returns do not match expected result'
        )

    # Modules
    def test_modules(self):
        expected_output = {
            'missing': [
                'iptable_filter',
                'iptable_nat',
                'ebtables',
                'bridge'
            ],
            'enabled': ['overlay']
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.lsmod_return(),
            '',
            '',
            '',
            '',
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_modules('centos', '7.2', True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values was not expected value'
        )

    # System Compatability
    def test_system_compatability_fail(self):
        expected_output = {
            'OS': 'PASS',
            'version': 'FAIL'
        }
        returns = profile.check_system_type('suse', '15', True)
        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_system_compatability_pass(self):
        expected_output = {
            'OS': 'PASS',
            'version': 'PASS'
        }
        returns = profile.check_system_type('rhel', '7.5', True)
        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # SELinux
    def test_selinux(self):
        expected_output = {
            'getenforce': 'disabled',
            'config': 'enforcing'
        }
        with mock.patch('ae_preflight.profile.execute_command') as cmd:
            cmd.return_value = b'Disabled'
            returns = profile.selinux('tests/fixtures/selinux_config', True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Agents
    def test_agents(self):
        expected_output = {
            'running': ['puppet-agent']
        }
        temp_pids = [1, 230, 9876]
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.get_pid(1, 'systemd'),
            command_returns.get_pid(230, 'puppet-agent'),
            psutil.NoSuchProcess(9876)
        ]
        with mock.patch('ae_preflight.profile.psutil.pids') as pids:
            pids.return_value = temp_pids
            with mock.patch(
                'ae_preflight.profile.psutil.Process',
                side_effect=mock_response
            ):
                returns = profile.check_for_agents(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Resolv.conf
    def test_resolv_conf(self):
        expected_output = {
            'search_domains': ['test.domain', 'another.domain'],
            'options': ['timeout:2']
        }
        returns = profile.inspect_resolv_conf(
            'tests/fixtures/resolv_conf',
            True
        )

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Open ports
    def test_open_ports_all(self):
        expected_output = {
            'eth0': {
                '80': 'open',
                '443': 'closed',
                '32009': 'closed',
                '61009': 'closed',
                '65535': 'closed'
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            'open',
            'closed',
            'closed',
            'closed',
            'closed'
        ]

        with mock.patch(
            'ae_preflight.profile.get_active_interfaces'
        ) as iface:
            iface.return_value = ['eth0']
            with mock.patch(
                'ae_preflight.profile.get_interface_ip_address'
            ) as ip:
                ip.return_value = '1.1.1.1'
                with mock.patch(
                    'ae_preflight.profile.check_for_socket',
                    side_effect=mock_response
                ):
                    returns = profile.check_open_ports(None, True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_open_ports_specified_interface(self):
        expected_output = {
            'eth0': {
                '80': 'open',
                '443': 'closed',
                '32009': 'closed',
                '61009': 'closed',
                '65535': 'closed'
            }
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            'open',
            'closed',
            'closed',
            'closed',
            'closed'
        ]

        with mock.patch(
            'ae_preflight.profile.get_interface_ip_address'
        ) as ip:
            ip.return_value = '1.1.1.1'
            with mock.patch(
                'ae_preflight.profile.check_for_socket',
                side_effect=mock_response
            ):
                returns = profile.check_open_ports('eth0', True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_open_ports_failure(self):
        expected_output = {}
        with mock.patch(
            'ae_preflight.profile.get_active_interfaces'
        ) as iface:
            iface.side_effect = IOError()
            returns = profile.check_open_ports(None, True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_open_ports_no_ip_addr(self):
        expected_output = {
            'eth0': 'No IP address assigned'
        }
        with mock.patch(
            'ae_preflight.profile.get_interface_ip_address'
        ) as ip:
            ip.return_value = None
            returns = profile.check_open_ports('eth0', True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # SUSE Infinity check
    def test_suse_infinity(self):
        expected_output = True
        returns = profile.suse_infinity_check(
            'tests/fixtures/systemd_system_conf',
            True
        )
        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Sysctl settings
    def test_sysctl_settings(self):
        expected_output = {
            'enabled': [
                'fs.inotify.max_user_watches',
                'fs.may_detach_mounts',
                'net.ipv4.ip_forward'
            ],
            'disabled': [
                'net.bridge.bridge-nf-call-ip6tables',
                'net.bridge.bridge-nf-call-iptables',
            ],
            'skipped': [],
            'incorrect': {}
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.all_sysctl_return(),
            b'net.bridge.bridge-nf-call-ip6tables = 0',
            b'net.bridge.bridge-nf-call-iptables = 0',
            b'fs.inotify.max_user_watches = 1048576',
            b'fs.may_detach_mounts = 1',
            b'net.ipv4.ip_forward = 1'
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_sysctl(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_sysctl_settings_skipped(self):
        expected_output = {
            'enabled': ['fs.may_detach_mounts'],
            'disabled': [
                'net.bridge.bridge-nf-call-ip6tables',
                'net.bridge.bridge-nf-call-iptables',
            ],
            'skipped': ['net.ipv4.ip_forward'],
            'incorrect': {
                'fs.inotify.max_user_watches': '8192'
            },
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.all_sysctl_return(skipped=True),
            b'net.bridge.bridge-nf-call-ip6tables = 0',
            b'net.bridge.bridge-nf-call-iptables = 0',
            b'fs.inotify.max_user_watches = 8192',
            b'fs.may_detach_mounts = 1'
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_sysctl(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_sysctl_settings_no_response(self):
        expected_output = {
            'enabled': [
                'fs.inotify.max_user_watches',
                'fs.may_detach_mounts',
            ],
            'disabled': [
                'net.bridge.bridge-nf-call-ip6tables',
                'net.bridge.bridge-nf-call-iptables',
                'net.ipv4.ip_forward'
            ],
            'skipped': [],
            'incorrect': {}
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            command_returns.all_sysctl_return(),
            b'net.bridge.bridge-nf-call-ip6tables = 0',
            b'net.bridge.bridge-nf-call-iptables = 0',
            b'fs.inotify.max_user_watches = 1048576',
            b'fs.may_detach_mounts = 1',
            b''
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_sysctl(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Directory checks
    def test_directory_paths(self):
        expected_output = [
            '/etc/chef',
            '/etc/salt'
        ]
        mock_response = mock.Mock()
        mock_response.side_effect = [
            True, True, False, False, False, False, False, False, False
        ]
        with mock.patch(
            'ae_preflight.profile.os.path.exists',
            side_effect=mock_response
        ):
            returns = profile.check_dir_paths(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # NTP checks
    def test_ntp_enabled(self):
        expected_output = {
            'using': 'ntpd',
            'installed': True,
            'enabled': True,
            'synched': True
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'/bin/ntpstat',
            command_returns.systemd_ntp_chronyd_status('ntpd'),
            command_returns.timedatectl_status(synched=True)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_chronyd_enabled(self):
        expected_output = {
            'using': 'chronyd',
            'installed': True,
            'enabled': True,
            'synched': True
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'',
            b'/sbin/chronyc',
            command_returns.systemd_ntp_chronyd_status('chronyd'),
            command_returns.timedatectl_status(synched=True)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_ntp_disabled(self):
        expected_output = {
            'using': None,
            'installed': 'ntpd',
            'enabled': False,
            'synched': False
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'/bin/ntpstat',
            command_returns.systemd_not_running_status(),
            b'',
            command_returns.timedatectl_status(synched=False)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_chronyd_disabled(self):
        expected_output = {
            'using': None,
            'installed': 'chronyd',
            'enabled': False,
            'synched': False
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'',
            b'/sbin/chronyd',
            command_returns.systemd_not_running_status(),
            command_returns.timedatectl_status(synched=False)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_timesyncd_enabled(self):
        expected_output = {
            'using': 'systemd-timesyncd',
            'installed': True,
            'enabled': True,
            'synched': True
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'',
            b'',
            b'/lib/systemd/systemd-timesyncd',
            command_returns.systemd_ntp_chronyd_status('timesyncd'),
            command_returns.timedatectl_status_timesyncd(synched=True)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_timesyncd_disabled(self):
        expected_output = {
            'using': None,
            'installed': 'systemd-timesyncd',
            'enabled': False,
            'synched': False
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'',
            b'',
            b'/lib/systemd/systemd-timesyncd',
            command_returns.systemd_not_running_status(),
            command_returns.timedatectl_status_timesyncd(synched=False)
        ]
        with mock.patch(
            'ae_preflight.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_for_ntp_synch(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # DNS Checks
    def test_dns_pass(self):
        test_domain = 'test.tld.com'
        expected_output = {
            'test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'},
            '*.test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'}
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            '1.2.3.4',
            '1.2.3.4'
        ]
        with mock.patch(
            'ae_preflight.profile.socket.gethostbyname',
            side_effect=mock_response
        ):
            returns = profile.check_dns_resolution(True, test_domain)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_dns_fail(self):
        test_domain = 'test.tld.com'
        expected_output = {
            'test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'},
            '*.test.tld.com': {'ip_addr': None, 'status': 'FAIL'}
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            '1.2.3.4',
            socket.gaierror
        ]
        with mock.patch(
            'ae_preflight.profile.socket.gethostbyname',
            side_effect=mock_response
        ):
            returns = profile.check_dns_resolution(True, test_domain)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    def test_dns_pass_wildcard_provided(self):
        test_domain = '*.test.tld.com'
        expected_output = {
            'test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'},
            '*.test.tld.com': {'ip_addr': '1.2.3.4', 'status': 'PASS'}
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            '1.2.3.4',
            '1.2.3.4'
        ]
        with mock.patch(
            'ae_preflight.profile.socket.gethostbyname',
            side_effect=mock_response
        ):
            returns = profile.check_dns_resolution(True, test_domain)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )

    # Test main and ensure that things work
    @mock.patch('ae_preflight.profile.argparse')
    def test_main_full_test(self, mock_patch):
        with mock.patch('ae_preflight.profile.get_os_info') as os:
            os.return_value = reporting_returns.os_return('ubuntu')
            with mock.patch(
                'ae_preflight.profile.check_system_type'
            ) as system:
                system.return_value = reporting_returns.system_compatability()
                with mock.patch(
                    'ae_preflight.profile.system_requirements'
                ) as req:
                    req.return_value = reporting_returns.memory_cpu()
                    with mock.patch(
                        'ae_preflight.profile.mounts_check'
                    ) as mount:
                        mount.return_value = reporting_returns.mounts()
                        with mock.patch(
                            'ae_preflight.profile.inspect_resolv_conf'
                        ) as resolv:
                            resolv.return_value = (
                                reporting_returns.resolv_conf()
                            )
                            with mock.patch(
                                'ae_preflight.profile.check_open_ports'
                            ) as port:
                                port.return_value = (
                                    reporting_returns.ports()
                                )
                                with mock.patch(
                                    'ae_preflight.profile.check_for_agents'
                                ) as agent:
                                    agent.return_value = (
                                        reporting_returns.agents()
                                    )
                                    with mock.patch(
                                        'ae_preflight.profile.check_modules'
                                    ) as module:
                                        module.return_value = (
                                            reporting_returns.modules()
                                        )
                                        with mock.patch(
                                            'ae_preflight.profile.'
                                            'check_sysctl'
                                        ) as sysctl:
                                            sysctl.return_value = (
                                                reporting_returns.sysctl()
                                            )
                                            with mock.patch(
                                                'ae_preflight.profile.'
                                                'check_dir_paths'
                                            ) as check_dir:
                                                check_dir.return_value = (
                                                    reporting_returns.check_dirs()  # noqa
                                                )
                                                with mock.patch(
                                                    'ae_preflight.profile.'
                                                    'check_for_ntp_synch'
                                                ) as check_ntp:
                                                    check_ntp.return_value = (
                                                        reporting_returns.ntp_check('ntpd', test_pass=True)  # noqa
                                                    )
                                                    with mock.patch(
                                                        'ae_preflight.profile.'
                                                        'check_dns_resolution'
                                                    ) as check_dns:
                                                        check_dns.return_value = (    # noqa
                                                            reporting_returns.dns_check(test_pass=True)  # noqa
                                                        )
                                                        profile.main()

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/ubuntu_pass.txt', 'r') as ubuntu:
            expected = ubuntu.readlines()

        differences = []
        with open('results.txt', 'r') as results:
            for line in results:
                if line not in expected:
                    differences.append(line)

        self.assertEquals(
            differences,
            [],
            'Differences were found in the results from what is expected'
        )
