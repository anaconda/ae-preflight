
from __future__ import absolute_import


from .fixtures import reporting_returns
from ae_preflight import report


import glob
import sys
import os


if sys.version_info[:2] >= (2, 7):
    from unittest import TestCase
else:
    from unittest2 import TestCase


class TestReporting(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        files = glob.glob('results.txt')
        for item in files:
            os.remove(item)

    def test_reporting_ubuntu(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('ubuntu')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

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

    def test_reporting_suse(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('suse')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = reporting_returns.infinity()
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'chronyd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/suse_pass.txt', 'r') as suse:
            expected = suse.readlines()

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

    def test_reporting_rhel(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('rhel')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = reporting_returns.selinux()
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/centos_pass.txt', 'r') as centos:
            expected = centos.readlines()

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

    def test_reporting_fail_suse(self):
        test_pass = False
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('suse')
        system_info['compatability'] = reporting_returns.system_compatability(
            test_pass
        )
        system_info['resources'] = reporting_returns.memory_cpu(test_pass)
        system_info['mounts'] = reporting_returns.mounts(
            test_pass
        )
        system_info['resolv'] = reporting_returns.resolv_conf(test_pass)
        system_info['ports'] = reporting_returns.ports(test_pass)
        system_info['agents'] = reporting_returns.agents(test_pass)
        system_info['modules'] = reporting_returns.modules(test_pass)
        system_info['selinux'] = None
        system_info['infinity_set'] = reporting_returns.infinity(test_pass)
        system_info['sysctl'] = reporting_returns.sysctl(test_pass)
        system_info['dir_paths'] = reporting_returns.check_dirs(test_pass)
        system_info['ntp'] = reporting_returns.ntp_check(
            'chronyd',
            test_pass=test_pass
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/suse_fail.txt', 'r') as suse:
            expected = suse.readlines()

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

    def test_reporting_fail_rhel(self):
        test_pass = False
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('rhel')
        system_info['compatability'] = reporting_returns.system_compatability(
            test_pass
        )
        system_info['resources'] = reporting_returns.memory_cpu(test_pass)
        system_info['mounts'] = reporting_returns.mounts(test_pass)
        system_info['resolv'] = reporting_returns.resolv_conf(test_pass)
        system_info['ports'] = reporting_returns.ports(test_pass)
        system_info['agents'] = reporting_returns.agents(test_pass)
        system_info['modules'] = reporting_returns.modules(test_pass)
        system_info['selinux'] = reporting_returns.selinux(test_pass)
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl(test_pass)
        system_info['dir_paths'] = reporting_returns.check_dirs(test_pass)
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=test_pass
        )
        system_info['dns'] = reporting_returns.dns_check(test_pass=test_pass)

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/centos_fail.txt', 'r') as centos:
            expected = centos.readlines()

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

    def test_reporting_ubuntu_trigger_warn_on_fs(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('ubuntu')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts(test_pass=False)
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/fs_warn.txt', 'r') as ubuntu:
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

    def test_reporting_ubuntu_trigger_warn_resolve(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('ubuntu')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf_warn()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/resolv_warn.txt', 'r') as ubuntu:
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

    def test_reporting_ubuntu_trigger_warn_on_interface(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('ubuntu')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports(test_pass=False)
        system_info['agents'] = reporting_returns.agents()
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/ports_warn.txt', 'r') as ubuntu:
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

    def test_reporting_ubuntu_trigger_warn_on_agents(self):
        system_info = {}
        system_info['profile'] = reporting_returns.os_return('ubuntu')
        system_info['compatability'] = reporting_returns.system_compatability()
        system_info['resources'] = reporting_returns.memory_cpu()
        system_info['mounts'] = reporting_returns.mounts()
        system_info['resolv'] = reporting_returns.resolv_conf()
        system_info['ports'] = reporting_returns.ports()
        system_info['agents'] = reporting_returns.agents(test_pass=False)
        system_info['modules'] = reporting_returns.modules()
        system_info['selinux'] = None
        system_info['infinity_set'] = None
        system_info['sysctl'] = reporting_returns.sysctl()
        system_info['dir_paths'] = reporting_returns.check_dirs()
        system_info['ntp'] = reporting_returns.ntp_check(
            'ntpd',
            test_pass=True
        )

        report.process_results(system_info)

        results_file = glob.glob('results.txt')
        self.assertEqual(
            len(results_file),
            1,
            'Did not find results file'
        )
        expected = []
        with open('tests/fixtures/agents_warn.txt', 'r') as ubuntu:
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
