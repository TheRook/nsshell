from __future__ import division, unicode_literals

import os
import ast

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    def __init__(self):
        self.SCRIPTS_DIR = os.path.join(os.getcwd(), 'scripts')
        self.LOG_DIR = os.path.join(os.getcwd(), 'logs')
        self.CLI_NO = ['false','off','n','no','none','/dev/null']
        self.CLI_YES = ['true','on','y','yes','yolo']

        self._get_config()

    def _get_config(self):
        """ load config from file, then load envvars.
            heirarchy is:
                envvars
                ./nsshell.conf
                /etc/nsshell.conf
                object attr defaults
            with envvars being the highest precendence and object attr defaults the lowest
            meaning if you set a config option via envvar, it overrides all others
        """
        import ConfigParser

        # if the module is called foo.bar.baz, module_name = foo
        module_name = __name__.split('.', 1)[0]

        config = ConfigParser.ConfigParser()
        for path in ['/etc/{0}/{0}.conf', './{0}.conf']:
            did_read = config.read(path.format(module_name))
            if did_read:
                for section in config.sections():
                    for k,v in config.items(section):
                        self.__dict__[k.upper()] = ast.literal_eval(v)

        # add env vars by doing NSSHELL_{config_opt}
        for k, v in self.__dict__.items():
            envvar = os.environ.get('{0}_{1}'.format(module_name.upper(), k), None)
            if envvar:
                self.__dict__[k.upper()] = ast.literal_eval(envvar)

config = Config()
