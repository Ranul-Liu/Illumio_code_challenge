# AWS flow log parser

This program is used to parse AWS flow logs. It requires one AWS flow log and one csv type lookup table file with header tag, dstport, and protocal type. It will count each type, and dstport and protocal combinations. The output will be written to a new file which does not exist. If inputs are not valid, the program will raise exceptions and quit.
Tests of simple valid inputs, complex files, empty imputs, wrong headers, existing output file, wrong version numbers, and others have been done.
It is possible to support more fields for tagging. If there is such need, I can define another constant that maps from field to index in log.

## Usage
`
python main.py [log file path] [lookup table file path] --output_path [output file path]
`

`log file path`: The path to the log file. It should be a plain text AWS version 2 flow log file.

`lookup table file path`: The path to the lookup table file. It should be a csv file with header dstport, protocol, tag.

`output file path`: The path and name of the output file. If it exists, program will not run. It is optional and by default it is counts.txt

### example
`
python main.py logs.txt lookup.csv --output_path output.txt
`
