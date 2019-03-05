#!/usr/bin/env python
import sys
from os import path

sys.path.append(path.dirname(sys.path[0]) + '\\logparser\\Slop')
import Slop

input_dir = '../logs/HDFS/'  # The input directory of log file
output_dir = 'Slop_result/'  # The output directory of parsing results
log_file = 'HDFS_2k.log'  # The input log file name
log_format = '<Date> <Time> <Pid> <Level> <Component>:<Content>'  # HDFS log format
tau = 0.5  # Message type threshold (default: 0.5)
regex = []  # Regular expression list for optional preprocessing (default: [])

parser = Slop.LogParser(logname=log_file, indir=input_dir, outdir=output_dir, log_format=log_format, tau=tau, rex=regex)
message = log_file

parser.parse_by_Spark(message)
#parser.parse_by_streaming(message,True)
#parser.outputResult()
