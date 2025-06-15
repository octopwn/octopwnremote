from setuptools import setup, find_packages
import re

VERSIONFILE="octopwnremote/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setup(
	# Application name:
	name="octopwnremote",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="tamas.jos@octopwn.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/octopwn/octopwnremote",

	zip_safe = False,
	#
	# license="LICENSE.txt",
	description="API for OctoPwn's REMOTECONTROLJS and REMOTECONTROL module",
	long_description="API for OctoPwn's REMOTECONTROLJS and REMOTECONTROL module",

	# long_description=open("README.txt").read(),
	python_requires='>=3.7',
	classifiers=[
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
        'websockets',
	],
	entry_points={
		'console_scripts': [
			'octopwn-remote-server = octopwnremote.server:main',
            'octopwn-remote-client = octopwnremote.client:main',
            'octopwn-remote-proxy = octopwnremote.proxy:main',
			'octopwn-remote-hashcat = octopwnremote.hashcat:main',
		],
	}
)
