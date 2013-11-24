There are two environment variables you will need to set when using this code:

BOTO_CONFIG  - Set this to the path to the boto.cfg file which contains your AWS
               credentials. This could be as simple as "./boto.cfg", and isn't needed
               at all if you've copied it to one of the standard locations
               such as "/etc/boto.cfg" or "~/.boto". See
               http://boto.readthedocs.org/en/latest/boto_config_tut.html
               for info on the format of the file.

PYTHONPATH   - Make sure this includes the path to the Halo Python library.
               This could be as simple as "../Halo". See
               http://docs.python.org/2/using/cmdline.html#envvar-PYTHONPATH
               for more info.
