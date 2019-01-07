[![Travis Status](https://travis-ci.org/oldarmyc/ae_preflight.svg?branch=master)](https://travis-ci.org/oldarmyc/ae_preflight.svg?branch=master)

Anaconda Enterprise Preflight Checks
======

#### Installing
To install the package do the following from the command line of your system.

```sh
git clone
cd ae_preflight
python setup.py install
```

#### Running
TO run the profiler from the command line enter in the following:
```sh
ae-profile
```

##### Options for running profiler
```
-i, --interface     Interface name i.e. eth0 or ens3 to check for open ports
-v, --verbose       Increase verbosity of the script
```

### Results

Results are located in a results.txt file in the directory that you ran the script from. The results file will warn and fail certain tests, and give
you reasons why and solutions on how to fix the issues.
