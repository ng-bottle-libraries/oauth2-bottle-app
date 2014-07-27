from setuptools import setup
from oauth2_bottle_app import __version__

if __name__ == '__main__':
    setup(name='oauth2_bottle_app', version=__version__,
          author='Samuel Marks', license='MIT', py_modules=['oauth2_bottle_app'],
          test_suite='tests')
