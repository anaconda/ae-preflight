
from __future__ import absolute_import
from .fixtures import command_returns
from system_profile import profile


import system_profile
import psutil
import sys


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
        pass

    def test_version(self):
        self.assertEquals(
            system_profile.__version__,
            '0.1.0',
            'Version does not match expected value'
        )

    # Execute command
    def test_execute_command_success(self):
        test_command = ['getenforce']
        selinux_status = None
        with mock.patch('system_profile.profile.Popen') as popen:
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
        with mock.patch('system_profile.profile.Popen') as popen:
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
        with mock.patch('system_profile.profile.Popen') as popen:
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
        with mock.patch('system_profile.profile.socket') as sock:
            sock.socket.return_value.connect_ex.return_value = 0
            port_status = profile.check_for_socket('eth0', '80', True)

        self.assertEquals(
            port_status,
            'open',
            'Did not get expected value on port status'
        )

    def test_socket_failure(self):
        port_status = 'Not Tested'
        with mock.patch('system_profile.profile.socket') as sock:
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
        with mock.patch('system_profile.profile.execute_command') as cmd:
            cmd.return_value = command_returns.ip_addr_show()
            ip_address = profile.get_interface_ip_address('eth0', False)

        self.assertEquals(
            expected_result,
            ip_address,
            'Did not get the expected IP address'
        )

    def test_get_ip_address_string(self):
        expected_result = '10.200.30.165'
        with mock.patch('system_profile.profile.execute_command') as cmd:
            cmd.return_value = command_returns.ip_addr_show().decode('utf-8')
            ip_address = profile.get_interface_ip_address('eth0', False)

        self.assertEquals(
            expected_result,
            ip_address,
            'Did not get the expected IP address'
        )

    # OS Info
    def test_os_info_rhel(self):
        expected_output = {
            'distribution': 'centos',
            'version': '7.5',
            'dist_name': 'CentOS Linux',
            'based_on': 'rhel'
        }
        with mock.patch(
            'system_profile.profile.distro.distro_release_info'
        ) as os:
            os.return_value = command_returns.distro_release_info('centos')
            with mock.patch('system_profile.profile.os.path.isfile') as file:
                file.return_value = True
                os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_suse(self):
        expected_output = {
            'distribution': 'sles',
            'version': '15',
            'dist_name': 'SLES',
            'based_on': 'suse'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, False, True]
        with mock.patch(
            'system_profile.profile.distro.distro_release_info'
        ) as os:
            os.return_value = {}
            with mock.patch(
                'system_profile.profile.distro.os_release_info'
            ) as distro:
                distro.return_value = (
                    command_returns.distro_release_info('suse')
                )
                with mock.patch(
                    'system_profile.profile.os.path.isfile',
                    side_effect=mock_response
                ):
                    os_info = profile.get_os_info(True)

        self.assertEquals(
            expected_output,
            os_info,
            'OS information returned was not the expected value'
        )

    def test_os_info_debian(self):
        expected_output = {
            'distribution': 'ec2',
            'version': '16.04',
            'dist_name': 'Ubuntu',
            'based_on': 'debian'
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [False, True]
        with mock.patch(
            'system_profile.profile.distro.distro_release_info'
        ) as os:
            os.return_value = command_returns.distro_release_info('ubuntu')
            with mock.patch(
                'system_profile.profile.os.path.isfile',
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
            'system_profile.profile.execute_command',
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
                'recommended': 0.0,
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
                'recommended': 100.0,
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
            'system_profile.profile.psutil.disk_partitions'
        ) as part:
            part.return_value = command_returns.psutil_disk_partitions()
            with mock.patch(
                'system_profile.profile.psutil.disk_usage',
                side_effect=mock_response
            ):
                with mock.patch(
                    'system_profile.profile.execute_command'
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
                'recommended': 0.0,
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
                'recommended': 100.0,
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
            'system_profile.profile.psutil.disk_partitions'
        ) as part:
            part.return_value = command_returns.psutil_disk_partitions()
            with mock.patch(
                'system_profile.profile.psutil.disk_usage',
                side_effect=mock_response
            ):
                with mock.patch(
                    'system_profile.profile.execute_command'
                ) as command:
                    command.return_value = b''
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
            'system_profile.profile.execute_command',
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
        with mock.patch('system_profile.profile.execute_command') as cmd:
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
            psutil._exceptions.NoSuchProcess(9876)
        ]
        with mock.patch('system_profile.profile.psutil.pids') as pids:
            pids.return_value = temp_pids
            with mock.patch(
                'system_profile.profile.psutil.Process',
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
            'system_profile.profile.get_active_interfaces'
        ) as iface:
            iface.return_value = ['eth0']
            with mock.patch(
                'system_profile.profile.get_interface_ip_address'
            ) as ip:
                ip.return_value = '1.1.1.1'
                with mock.patch(
                    'system_profile.profile.check_for_socket',
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
            'system_profile.profile.get_interface_ip_address'
        ) as ip:
            ip.return_value = '1.1.1.1'
            with mock.patch(
                'system_profile.profile.check_for_socket',
                side_effect=mock_response
            ):
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
            'enabled': ['net.ipv4.ip_forward'],
            'disabled': [
                'net.bridge.bridge-nf-call-ip6tables',
                'net.bridge.bridge-nf-call-iptables',
                'fs.may_detach_mounts'
            ]
        }
        mock_response = mock.Mock()
        mock_response.side_effect = [
            b'net.bridge.bridge-nf-call-ip6tables = 0',
            b'net.bridge.bridge-nf-call-iptables = 0',
            b'',
            b'net.ipv4.ip_forward = 1'
        ]
        with mock.patch(
            'system_profile.profile.execute_command',
            side_effect=mock_response
        ):
            returns = profile.check_sysctl(True)

        self.assertEquals(
            expected_output,
            returns,
            'Returned values did not match expected output'
        )
