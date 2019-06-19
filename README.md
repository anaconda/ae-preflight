[![Travis Status](https://travis-ci.org/Anaconda-Platform/ae-preflight.svg?branch=master)](https://travis-ci.org/Anaconda-Platform/ae-preflight.svg?branch=master) &nbsp; [![Anaconda-Server Badge](https://anaconda.org/aeadmin/ae_preflight/badges/latest_release_date.svg)](https://anaconda.org/aeadmin/ae_preflight) &nbsp; [![Anaconda-Server Badge](https://anaconda.org/aeadmin/ae_preflight/badges/version.svg)](https://anaconda.org/aeadmin/ae_preflight)

Anaconda Enterprise Preflight Checks
======

#### Installing
To install the package do the following from the command line of your system. For system specific instructions see [detailed instructions](#detailed-install-instructions).

```sh
git clone
cd ae_preflight
python setup.py install
```

#### Running
To run the profiler from the command line enter in the following:
```sh
ae-preflight
```

##### Options for running profiler
```
-i, --interface     Interface name i.e. eth0 or ens3 to check for open ports
-v, --verbose       Increase verbosity of the script
--hostname          Check hostname to ensure that DNS can be resolved for TLD and wildcard DNS
```

### Results

Results are located in a results.txt file in the directory that you ran the script from. The results file will warn and fail certain tests, and give
you reasons why and solutions on how to fix the issues.

***

### Detailed install instructions

#### CentOS 7.X

```sh
# Install requirements
yum install epel-release -y
yum install git python-psutil -y

# Git clone and install
git clone https://github.com/Anaconda-Platform/ae-preflight.git
cd ae-preflight
python setup.py install

# Run program
ae-preflight
```

#### Ubuntu 16.04

```sh
# Update apt-caches and install requirements
apt-get update
apt-get install python3-psutil git python3-setuptools -y

# Git clone and install
git clone https://github.com/Anaconda-Platform/ae-preflight.git
cd ae-preflight
python setup.py install

# Run prechecks
ae-preflight
```

#### Suse 12

```sh
# Install dependencies
zypper install -y git python-psutil

# Git clone and install
git clone https://github.com/Anaconda-Platform/ae-preflight.git
cd ae-preflight
python setup.py install

# Run prechecks
ae-preflight
```

#### Conda Environment

##### Install requirements
```sh
# Install from yum (CentOS and RHEL)
yum install bzip2 -y

# Install from apt (Ubuntu)
apt-get install bzip2 -y

# Install from zypper (Suse)
zypper install -y bzip2
```

##### Install and setup conda environment
```sh
# Get miniconda and install it
curl -O https://repo.anaconda.com/miniconda/Miniconda2-4.6.14-Linux-x86_64.sh
bash Miniconda2-4.6.14-Linux-x86_64.sh  # Accept the license and take the defaults

# Source bashrc to pick up conda paths
source ~/.bashrc

# Create profile, and preflight package
conda create -n python37 python=3.7 psutil -y
conda activate python37
conda install -c aeadmin ae_preflight -y

# Run prechecks
ae-preflight
```
