## Python Meterpreter

Running unit tests:

```
# Only required if less than python 3.3
pip install mock

# Run the tests
python -m unittest discover -v ./tests
```

Running a single test failure:

```
python3 ./tests/test_file.py class_name
python3 ./tests/test_file.py class_name.method_name

# For example
python3 ./tests/test_ext_server_stdapi.py TestExtServerStdApi.test_stdapi_net_config_get_interfaces_via_osx_ifconfig
```
