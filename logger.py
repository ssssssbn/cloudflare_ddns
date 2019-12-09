#! /usr/bin/env python
#! /bin/env python
# coding=utf-8

# import logger in other project and init with Logger(self, logger_name, log_level, log_filename, log_mode, log_format, log_encoding, log_TimedRotatingFile, log_TimedRotatingFile_when, log_TimedRotatingFile_interval) , then use thisfilename.Logger.debug/info/warning/error/critical(str) to log information.

import os;
import time;
import logging;
from logging import handlers;

class Logger:
	def __init__(self, logger_name, log_level, log_filename, log_mode, log_format, log_encoding, log_TimedRotatingFile, log_TimedRotatingFile_when, log_TimedRotatingFile_interval, log_TimedRotatingFile_backupCount):
		self.name = logger_name;
		self.level = log_level;
		self.filename = log_filename;#'cloudflare_ddns.log'
		self.mode = log_mode;#a
		self.format = log_format;#'%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'
		self.encoding = log_encoding;#'utf-8'
		self.TimedRotatingFile = log_TimedRotatingFile;
		self.TimedRotatingFile_when = log_TimedRotatingFile_when;
		self.TimedRotatingFile_interval = log_TimedRotatingFile_interval;
		self.TimedRotatingFile_backupCount = log_TimedRotatingFile_backupCount;
		
		self.logger = logging.getLogger(self.name);
		self.logger.setLevel(self.level);

		formatter = logging.Formatter(self.format);#'%(asctime)s-%(levelname)s: %(message)s' #'%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'

		if not self.TimedRotatingFile:
			self.file_handler = logging.FileHandler(self.filename, mode = self.mode, encoding = self.encoding);
			self.file_handler.setLevel(self.level);
			self.file_handler.setFormatter(formatter);
		else:
			self.time_rotating_file_handler = handlers.TimedRotatingFileHandler(filename = self.filename, when = self.TimedRotatingFile_when, interval = self.TimedRotatingFile_interval, backupCount = self.TimedRotatingFile_backupCount);
			self.time_rotating_file_handler.setLevel(self.level);
			self.time_rotating_file_handler.setFormatter(formatter);


		self.stream_handler = logging.StreamHandler();
		self.stream_handler.setLevel(self.level);
		self.stream_handler.setFormatter(formatter);

		if not self.TimedRotatingFile:
			self.logger.addHandler(self.file_handler);
		else:
			self.logger.addHandler(self.time_rotating_file_handler);
		self.logger.addHandler(self.stream_handler);


	def SetLogLevel(self, level):
		self.logger.setLevel(level);
		if not self.TimedRotatingFile:
			self.file_handler.setLevel(level);
		else:
			self.time_rotating_file_handler.setLevel(level);
		self.stream_handler.setLevel(level);
		return;
		
		
def test(class_logger, logger):
	class_logger.SetLogLevel(logging.DEBUG);
	
	logger.debug('debug');
	logger.info('info');
	logger.warning('warning');
	logger.error('error');
	logger.critical('critical');

	class_logger.SetLogLevel(logging.INFO);

	logger.debug('debug');
	logger.info('info');
	logger.warning('warning');
	logger.error('error');
	logger.critical('critical');

	class_logger.SetLogLevel(logging.WARNING);

	logger.debug('debug');
	logger.info('info');
	logger.warning('warning');
	logger.error('error');
	logger.critical('critical');

	class_logger.SetLogLevel(logging.ERROR);

	logger.debug('debug');
	logger.info('info');
	logger.warning('warning');
	logger.error('error');
	logger.critical('critical');

	class_logger.SetLogLevel(logging.CRITICAL);

	logger.debug('debug');
	logger.info('info');
	logger.warning('warning');
	logger.error('error');
	logger.critical('critical');
	return;

if __name__ == "__main__":
	filepath = '/tmp/test_logger';
	#if not os.path.exists('/tmp'):
	#	os.makedirs('/tmp');
	#	os.makedirs(filepath);
	#el
	if not os.path.exists(filepath):
		os.makedirs(filepath);
	class_logger = Logger('logger', logging.DEBUG, filepath + '/test.log', 'a', '%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s', 'utf-8', True, 'D', 1);
	logger = class_logger.logger;
	test(class_logger, logger);
	exit(0);