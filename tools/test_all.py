#!/usr/bin/env python

import subprocess, sys, traceback, os, multiprocessing

configurations = []

# Building functions
def prepare_configuration():
	if subprocess.call(["mkdir", "build"]):
		raise ValueError("Preparation of build folder failed.")
	os.chdir("build")

def config_configuration(config):
	args = ["cmake"]
	args.extend(config['build'])
	args.extend([".."])
	if subprocess.call(args):
		raise ValueError("CMake configuration failed.")

def build_configuration():
	if subprocess.call(["make", "-j", str(multiprocessing.cpu_count())]):
		raise ValueError("Building failed.")

def test_configuration(config):
	args = ["ctest", "--output-on-failure", "-j", str(multiprocessing.cpu_count())]
	args.extend(config['test'])
	if subprocess.call(args):
		print("Tests failed: %s" % config["build"])

def clean_configuration():
	os.chdir("..")
	if subprocess.call(["rm", "-rf", "build"]):
		raise ValueError("Cleaning build directory failed.")

def conf_build_test_clean(config):
	try:
		prepare_configuration()
		config_configuration(config)
		build_configuration()
		test_configuration(config)
	except Exception as e:
		print("Build failed: ", str(config), e)
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_tb(exc_traceback)
	clean_configuration()



# Setup configurations
def extend_default_config(extension):
	default_conf = [
		'-DSEED=ZERO',
		'-DBENCH=0'
	]
	default_conf.extend(extension)
	return default_conf

# test Relic standard configuration
configurations.append({'build': extend_default_config([]), 'test': ['-E', 'test_bn|test_fpx']})

# test ECC configurations
configurations.append({'build': extend_default_config(['-DFP_PRIME=255', "-DEC_METHD='PRIME'", "-DEP_METHD='PROJC;LWNAF;LWNAF;BASIC'"]), 'test': ['-E', 'test_bn|test_fb|test_fpx|test_eb']})
configurations.append({'build': extend_default_config(['-DFP_PRIME=255', "-DEC_METHD='EDWARD'", "-DED_METHD='PROJC;LWNAF;LWNAF;BASIC'"]), 'test': ['-E', 'test_bn|test_fb|test_fpx|test_eb']})
configurations.append({'build': extend_default_config(['-DFP_PRIME=255', "-DEC_METHD='EDWARD'", "-DED_METHD='EXTND;LWNAF_MIXED;LWNAF_MIXED;BASIC'"]), 'test': ['-E', 'test_bn|test_fb|test_fpx|test_eb|test_ec']})


for config in configurations:
	conf_build_test_clean(config)
