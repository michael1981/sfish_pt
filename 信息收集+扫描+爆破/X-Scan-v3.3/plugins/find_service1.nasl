#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17975);
 script_version ("$Revision: 1.236 $");
 
 script_name(english:"Unknown Service Detection: GET Request");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin performs service detection." );
 script_set_attribute(attribute:"description", value:
"This plugin is a complement of find_service.nasl.  It sends a GET
request to the remaining unknown services and tries to identify them." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

 script_summary(english:"Sends 'GET' to unknown services and look at the answer");
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");

 if ( NASL_LEVEL < 3203 )
  script_dependencie("find_service.nes", "cifs445.nasl");
 else
  script_dependencie("find_service.nasl", "cifs445.nasl");
# Do *not* add a port dependency  on "Services/unknown"
# Some scripts must run after this script even if there are no
# unknown services
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");

function is_lsof_diskmonitor(banner)
{
  local_var	len, i, z;

  len = strlen(banner);
  if (len < 416) return 0;
  if (substr(banner, 0, 3) != '0000') return 0;
  if (substr(banner, len - 2) != '\r\n') return 0;

  for (i = 0; i < len - 2; i ++)
  {
    z = ord(banner[i]);
    if ((z < 48 || z > 57) &&	# 0 .. 9
        (z < 97 || z > 102))	# a .. f
      return 0;
  }

  z = hex2raw(s: substr(banner, 4, 7));
  z = (ord(z[0]) << 8) | ord(z[1]);
  if (z + 2 == len) return 1;
  return 0;
}

if ( get_kb_item("global_settings/disable_service_discovery") ) exit(0);


port = get_unknown_svc();
if (! port) exit(0);
if (! get_port_state(port)) exit(0);

# If the service displays a banner on connection, find_service.c does not
# send a GET request. However, if a GET request was sent and the service
# remains silent, the get_http KB entry is void

r0 = get_kb_item('FindService/tcp/'+port+'/spontaneousHex');	# Banner?
if ( ! isnull(r0) )
     r0 = hex2raw(s:r0);
else 
     r0 = get_kb_item('FindService/tcp/'+port+'/spontaneous');
get_sent = 1;

r0_len = strlen(r0);
if (r0_len > 0)	# We have a spontaneous banner
{
 get_sent = 0;	# spontaneous banner => no GET request was sent by find_service

###################################################
######## Updates for "spontaneous" banners ########
###################################################

if (r0 =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+')
{
 debug_print('Fake IDENTD found on port ', port, '\n');
 register_service(port: port, proto: 'fake-identd');
 set_kb_item(name: 'fake_identd/'+port, value: TRUE);
 exit(0);
}

if (match(string: r0, pattern: "<Rastrac>Ping</Rastrac><Rastrac><RastracMessage><MessageType>RastracVehicleState</MessageType><ID>*"))
{
 register_service(port: port, proto: 'rastrac');
 security_note(port: port, data: 'Rastrac, a system to track vehicles, seems to be running on this port.\nSee http://www.rastrac.net/');
}

# OpenVPN is usually running on UDP, but it can be launched on TCP
# Type : spontaneous
# 0x00: 00 0E 40 84 EE 95 FD A9 2F A1 87 00 00 00 00 00 ..@...../.......
# 0x10:
# Three other banners (collected on another machine):
# 00000 00 0e 40 68 4a b5 61 b9 d8 4f 41 00 00 00 00 00
# 00000 00 0e 40 7d 2b 45 19 2c 84 3b a4 00 00 00 00 00
# 00000 00 0e 40 1b 50 e2 da 8e 05 48 56 00 00 00 00 00
#
# A newer OpenVPN version?
# 0000000 00 2a 40 bc fd 34 aa 53 65 ef a4 fa 60 30 7f 56
# 0000020 69 99 5b 63 80 02 1c 4f 64 79 84 54 0c 4d 36 00
# 0000040 00 00 01 4a 27 94 6e 00 00 00 00 00
# 0000054
#
# 0000000 00 2a 40 e3 e9 4c 1e 7e db 95 c6 2a 4d 6a f3 21
# 0000020 70 ec b8 cc 52 80 39 22 88 0c 1c ae a1 a4 c7 00
# 0000040 00 00 01 4a 27 94 db 00 00 00 00 00
# OpenVPN can be more talkative: it resends this data after a while

if ( r0_len >= 16)
{
  x2 = ord(r0[0]) * 256 + ord(r0[1]);
  if (x2 >= 14 && r0_len >=  x2+2 && r0[2] == '\x40' && substr(r0, x2-3, x2+1) == '\0\0\0\0\0')
 {
   report_service(port: port, svc: 'openvpn');
   exit(0);
 }
}

if (match(string: r0, pattern: 'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *'))
{
 report_service(port: port, svc: 'smsc');
 exit(0);
}

if (r0 == '\x00\x00\x00\x0D\xD5\xF2Who are you?\x0A\x00')
{
 # Port doc1lm (3161/tcp)
 # PatrolAgent (BMC Patrol)
 report_service(port: port, svc: 'patrol-agent');
 exit(0);
}


if ( "com.plumtree.content.rdbms.database" >< r0 )
{
 report_service(port: port, svc: 'java-plumtree-server');
 exit(0);
}

#
# aced0005 = header fo a serialized object stream 
# (java.io.ObjectOutputStream)
# 
if (r0_len >= 4 && substr(r0, 0, 3) == '\xAC\xED\x00\x05' )
{
 report_service(port: port, svc: 'java-listener');
 exit(0);
}

if ( '\x00\x00\x00\x0bSynergy' >< r0 )
{
 # Synergy Server
 report_service(port: port, svc: 'synergys');
 exit(0);
}

if ("HP OpenView Storage Data Protector" >< r0 )
{
 report_service(port: port, svc: 'hp_openview_dataprotector');
 exit(0);
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a . 
#
# 00: 39 3A 32 38 3A 31 32 20 32 30 30 38 2F 30 36 2F 9:28:12 2008/06/
# 10: 32 32 0A 22. 
#
# 0x00: BF C0 C8 C4 20 31 32 3A 35 36 3A 30 30 20 32 30 .... 12:56:00 20
# 0x10: 30 38 2D 30 37 2D 30 39 0A 08-07-09. 
#
# 0x00: 39 3A 30 38 3A 35 33 20 30 32 2E 30 38 2E 32 30 9:08:53 02.08.20
# 0x10: 30 38 0A					08.
#
# 0x00: 31 2E 33 35 2E 34 39 20 31 33 2F 30 38 2F 32 30 1.35.49 13/08/20
# 0x10: 30 38 0A                                        08. 
#
# 0x00: A4 55 A4 C8 20 30 37 3A 35 33 3A 32 30 20 32 30 .U.. 07:53:20 20
# 0x10: 30 38 2F 31 31 2F 31 37 0A 08/11/17. 
#
# 0x00: 32 31 3A 30 32 3A 35 36 20 31 34 2E 31 32 2E 30 21:02:56 14.12.0
# 0x10: 38 0A 8. 
#
# 0x00: 31 37 3A 31 37 3A 30 33 20 31 2E 35 2E 32 30 30 17:17:03 1.5.200
# 0x10: 39 0A 9.
#
if (ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:r0) ||
# No ^ at the begining of the line!
ereg(pattern:' ([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +20[0-3][0-9]-(0?[1-9]|1[0-2])-([0-2]?[0-9]|3[01])[ \t\r\n]*$', string: r0) ||
ereg(pattern:' ([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +20[0-3][0-9]/(0?[1-9]|1[0-2])/([0-2]?[0-9]|3[01])[ \t\r\n]*$', string: r0) ||
#
ereg(pattern:'^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] ([0-2]?[0-9]|3[01])\\.(0?[1-9]|1[0-2])\\.20[0-3][0-9][ \t\r\n]*$', string: r0) ||
# Daytime in German
ereg(pattern:"^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +([0-2][0-9]|3[01])\.(0[1-9]|1[0-2])\.(19|20)?[0-9][0-9][ \t\r\n]*$", string: r0)
|| ereg(pattern: '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +20[0-3][0-9]-(0?[1-9]|1[0-2])-([0-2]?[0-9]|3[01])[ \t\r\n]*$', string: r0)
|| ereg(pattern: '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] ([0-2][0-9]|3[01])\\.(0?[1-9]|1[0-2])\\.+20[0-3][0-9][ \t\r\n]*$', string: r0)
|| ereg(pattern: '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +20[0-3][0-9]/(0?[1-9]|1[0-2])/([0-2][0-9]|3[01])[ \t\r\n]*$', string: r0)
|| ereg(pattern: '^([01]?[0-9]|2[0-3])\\.[0-5][0-9]\\.[0-5][0-9] ([0-2]?[0-9]|3[01])/(0?[1-9]|1[0-2])/+20[0-3][0-9][ \t\r\n]*$', string: r0)
)
{
 report_service(port: port, svc: 'daytime');
 exit(0);
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if (r0 =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}

if (match(string: r0, pattern: '220 *FTP Server ready\r\n'))
{
 report_service(port: port, svc: 'ftp');
 exit(0);
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if (match(string: r0, pattern: '"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*'))
{
 register_service(port: port, proto: 'sieve');
 security_note(port: port, data: 'Sieve mail filter daemon seems to be running on this port');
 exit(0);
}

# I'm not sure it should go here or in find_service2...
if (match(string: r0, pattern: '220 Axis Developer Board*'))
{
 report_service(port: port, svc: 'axis-developer-board');
 exit(0);
}

if (
  match(string: r0, pattern: '  \x5f\x5f\x5f           *Copyright (C) 1999, 2000, 2001, 2002 Eggheads Development Team') ||
  ("(Eggdrop v" >< r0 && " (C) 1997 Robey Pointer " >< r0) ||
  # with stealth-telnets set to 1.
  '\r\nNickname.\r\n' == r0 ||
  ('\r\nNickname.\r\n' >< r0 && "You don't have access." >< r0)
)
{
 register_service(port:port, proto:"eggdrop");
 security_note(port:port, data:'An Eggdrop IRC bot is listening on this port.');
 exit(0);
}

# Music Player Daemon from www.musicpd.org
if (ereg(string: r0, pattern: '^OK MPD [0-9.]+\n'))
{
 report_service(port: port, svc: 'mpd');
 exit(0);
}

# Eudora Internet Mail Server ACAP server.
if ("* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< r0)
{
 report_service(port: port, svc: 'acap');
 exit(0);
}

# Sophos Remote Messaging / Management Server.
if (
  "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r0 ||
  "IOR:000000000000002649444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r0
)
{
 report_service(port: port, svc: 'sophos_rms');
 exit(0);
}

# CaliberRM SQM Monitor
if ("IOR:012020201f00000049444c3a43616c696265722f47656e65726963466163746f72793a312e30" >< r0)
{
 report_service(port: port, svc: 'caliberrm_sqm_monitor');
 exit(0);
}

# Ipswitch Collaboration Suite WorkgroupShare Server.
if (egrep(pattern:"^OK WorkgroupShare .+ server ready", string:r0))
{
  report_service(port:port, svc:"WorkgroupShare");
  exit(0);
}

# dovecot IMAP server running on FreeBSD 7.0
if (r0 == '* OK DogNet Mail Server Ready.\r\n')
{
  report_service(port: port, svc:'imap');
  exit(0);
}

if (r0 =~ '^\\* *BYE ')
{
  register_service(port: port, proto:'imap');
  security_note(port: port, data: 'The IMAP server rejects connection from our host. We cannot test it');
  exit(0);
}

# General case should be handled by find_service_3digits
if (match(string: r0, pattern: '200 CommuniGatePro PWD Server * ready*'))
{
 report_service(port: port, svc: 'pop3pw');
 exit(0);
}


# Should be handled by find_service.nasl already
if (r0 =~ "^RFB 00[0-9]\.00")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}
if (r0 =~ "^RFB 003\.889")
{
  register_service(port:port, proto:"ard");
  security_note(port:port, data:"Apple Remote Desktop is running on this port.");
  exit(0);
}


if (r0 =~ '^welcome to the pioneers-meta-server version [0-9]\\.')
{
 register_service(port:port, proto:'pioneers-meta-server');
 security_note(port:port, data:"A meta server for the game Pioneers is running on this port.");
 exit(0);
}

# MA 2008-08-30: AIX lpd - Yes! This is a "spontaneous" banner
if (r0 =~ "^[0-9]+-[0-9]+ ill-formed FROM address.$")
{
 register_service(port:port, proto:'lpd');
 security_note(port: port, 'An LPD server (probably AIX) is running on this
 port');
 exit(0);
}

# German W2K3 qotd
if (ereg(string: r0, multiline: 1, pattern: '..........\n\\((Federico Fellini|Juliette Gréco|Berthold Brecht|Volksweisheit|Mark Twain|Bertrand Russell|Helen Markel|Fritz Muliar|Anatole France|Albert Einstein|Oscar Wilde|August von Kotzebue|Tschechisches Sprichwort|Schweizer Sprichwort|Mark Twain|Machado de Assis)\\)$'))
{
 register_service(port:port, proto: "qotd");
 security_note(port: port, data: "qotd seems to be running on this port");
 exit(0);
}

# From Jim Heifetz
# Runs on port 10007 of z/OS Communication Server
# It always returns an eight digit number.

if (r0 =~ '^0000[0-9][0-9][0-9][0-9]$')
{
 register_service(port:port, proto:"mvs-capacity");	# should we call it bpxoinit?
 security_note(port: port, data: "BPXOINIT (MVS capacity) seems to be running on this port");
 exit(0);
}

if ("220 Ipswitch Notification Server" >< r0)
{
  register_service(port:port, proto:'ipswitch_ns');
  security_note(
    port:port, 
    data:"An Ipswitch Notification Server is running on this port."
  );
 exit(0);
}

if (":onx{" >< r0 && ':name["shinkuro"]' >< r0 && ':verb["hello"]' >< r0)
{
  register_service(port:port, proto:'shinkuro');
  security_note(
    port:port, 
    data:"A Shinkuro peer is running on this port."
  );
 exit(0);
}

# Submitted by Timothy Smith.
#
# nb: default port is TCP 8181.
if (
  "<KU_goodbye>Access not allowed" >< r0 && 
  "Check the InterMapper server&apos;s" >< r0
)
{
  register_service(port:port, proto:'intermapperd');
  security_note(
    port:port, 
    data:'An InterMapper service is listening on this port.'
  );
 exit(0);
}

# Submitted by w laoye.
#
# Spontaneous banner; eg,
# 
#   Temp.= 31.0, 37.0, 37.0; Rot.= 3970, 2576, 2700
#   Vcore = 1.74, 1.74; Volt. = 3.38, 5.08, 12.40, -11.35, -4.90
if (
  (stridx(r0, "Temp.=") == 0 || stridx(r0, '\nTemp.=') == 0) &&
  "; Rot.= " >< r0 &&
  '\nVcore = ' >< r0 &&
  "; Volt. = " >< r0
)
{
  register_service(port:port, proto:'mbmon');
  security_note(
    port:port, 
    data:'An mbmon (MotherBoard Monitor) daemon is listening on this port.'
  );
 exit(0);
}

# Spontaneous banner on TCP port 5405 - For example
# 0x00:  1B 00 02 00 54 49 54 41 4E 49 43 2D 42 44 43 00 ....TITANIC-BDC.
# 0x10:  00 00 00 00 00 00 01 00 01 00 00 00 00          .............
if (r0_len == 29 && substr(r0, 0, 3) == '\x1B\x00\x02\x00' &&
    substr(r0, r0_len - 6) == '\x00\x01\x00\x00\x00\x00')
{
  for (i = 4; i < r0_len && r0[i] != '\0'; i ++)
   ;  
  register_service(port:port, proto: "netsupport");
  security_note(port: port, data: "NetSupport client is running on this port");
  if (i > 4)
   security_note(port: port, 
data: 'According to NetSupport, the name of this host is\n' + substr(r0, 4, i - 1));
  exit(0);
}

# Spontaneous banner from hudlite-server 1.4.6:
#   :HUDserver NOTICE AUTH :*** Looking up your hostname...
#   :HUDserver NOTICE AUTH :*** Checking Ident
#   :HUDserver NOTICE AUTH :*** No Ident response
#   :HUDserver NOTICE AUTH :*** Found your hostname
if (":HUDserver NOTICE AUTH" >< r0)
{
  register_service(port:port, proto:'irc');
  security_note(
    port:port, 
    data:'An IRC server used by HUDlite-server, a backend for HUDlite,\nis running on this port.'
  );
 exit(0);
}

# Submitted by Michael Shor.
#
# Listens by default on TCP port 4949.
# Spontaneous banner; "# munin node at nixon.lab"
# More info: http://munin.projects.linpro.no/
if (r0 =~ '^# munin node at ')
{
 register_service(port:port, proto:"munin-node");
 security_note(port:port, data:'A munin-node daemon is listening on this port.  This service is used\nby the network monitoring tool Munin for monitoring individual hosts.');
 exit(0);
}

# Submitted by Adam J Richardson.
#
# Spontaneous banner:
#   :dircproxy NOTICE AUTH :Looking up your hostname...
#   :dircproxy NOTICE AUTH :Got your hostname.
# More info: http://dircproxy.securiweb.net/
if (r0 =~ '^:dircproxy NOTICE AUTH')
{
 register_service(port:port, proto:"irc-bnc");
 security_note(port:port, data:'dircproxy, an IRC proxy server, is listening on this port.');
 exit(0);
}

# Submitted by Boogiebruva.
#
# Listens by default on TCP port 7777.
# Spontaneous banners: "cpu:  0.00 mem:-7223629312.00 s"
#                      "cpu:100.00 mem:83.63 swp:10032"
if (r0 =~ '^cpu: *[0-9][0-9.]+ mem:')
{
 register_service(port:port, proto:"jmond");
 security_note(port:port, data:'A jMon distributed resource monitor daemon is listening on this port.');

 exit(0);
}

# Listens on TCP port 2277.
# Spontaneous banner:
#   xqueue_id\0AAP0001752000146B2F1C8\0continue\010485760
if (r0 =~ '^xqueue_id\0[0-9A-H]+\0continue\0[0-9]+')
{
 register_service(port:port, proto:"kas-ap-process-server");
 security_note(port:port, data:'A Kaspersky Anti-Spam Filtration Server is listening on this port.');

 exit(0);
}

# Submitted by Aaron Michael Daugherty
#
# Listens by default on TCP port 4750.
# Spontaneous banners: "00000006-1;7350000001810;65;0;d50;d50;0"
#                      "00000006-1;7350000001810;65;0;b80;b80;0"
if (r0 =~ '^[0-9]+-[0-9];[0-9]+;[0-9]+;[0-9];[0-9a-h]+;[0-9a-h]+;[0-9]$')
{
 register_service(port:port, proto:"bladelogic_rscd");
 security_note(port:port, data:'A BladeLogic remote system call daemon (RSCD) is listening on this\nport.');

 exit(0);
}

# Submitted by Heath S. Hendrickson.
#
# Listens by default on TCP port 5280 by default.
if (r0 =~ '^[0-9]+ [0-9]+ pid$')
{
 register_service(port:port, proto:"autosys_client");
 security_note(port:port, data:'A Unicenter AutoSys Job Management remote client is listening on this\nport.');

 exit(0);
}

# Spontaneous banner:
#   RPY 0 0 . 0 118
#   Content-Type: application/beep+xml
#   
#   <greeting><profile uri="http://xml.resource.org/profiles/NULL/ECHO"/></greeting>END
# More info: http://www.rfc-editor.org/rfc/rfc3080.txt
if (
  'application/beep+xml' >< r0 &&
  '<greeting>' >< r0 &&
  r0 =~ '^RPY 0 0'
)
{
 register_service(port:port, proto:"beep");
 security_note(port:port, data:'A BEEP (Blocks Extensible Exchange Protocol) peer is listening on this\nport.');
 exit(0);
}

# Submitted by Zach Jansen.
#
# No default port.
# Spontaneous banner:
#   <AgentInfo><Version>6, 3, 2, 858</Version></AgentInfo>
if (
  stridx(r0, "<AgentInfo><Version>") == 0 &&
  # nb: 22 == strlen("</Version></AgentInfo>")
  (stridx(r0, "</Version></AgentInfo>") == r0_len - 22 - 1)
)
{
  local_var report, v;

  register_service(port:port, proto:"patchlink_update_agent");

  report = "This is the listener port, or 'ping port', for a PatchLink Update Agent";
  v = strstr(r0, "<Version>") - "<Version>";
  v = v - strstr(v, "</Version");
  if (v)
  {
    v = str_replace(find:", ", replace:".", string:v);

    set_kb_item(name:"PatchLink_Update_Agent/"+port+"/Version", value:v);

    report += ',\n' +
      'which the banner identifies as version ' + v;
  }
  report += '.\n';
  
  security_note(port:port, data:report);
  exit(0);
}

# Listens on port 1793 by default if TCP support is enabled.
#
# Spontaneous banner:
#   0x00: 49 48 55 06 3E 00 IHU.>.
# More info: http://ihu.sourceforge.net/
if (r0_len == 6 && r0 == 'IHU\x06\x3e\x00')
{
  register_service(port:port, proto:"ihu");
  security_note(port:port, data:'An IHU (I Hear U) daemon is listening on this port.');
  exit(0);
}

# Submitted by Timothy Doty.
#
# Listens on port 3261 by default
#
# Spontaneous banner:
#   0x00: 1B 5B 32 4A 53 74 61 72 57 69 6E 64 20 69 53 43 .[2JStarWind iSC
#   0x10: 53 49 20 54 61 72 67 65 74 20 76 33 2E 35 2E 31 SI Target v3.5.1
#   0x20: 20 28 42 75 69 6C 64 20 32 30 30 37 31 32 30 34 (Build 20071204
#   0x30: 2C 20 57 69 6E 33 32 29 0D 0A 43 6F 70 79 72 69 , Win32)..Copyri
#   0x40: 67 68 74 20 28 63 29 20 52 6F 63 6B 65 74 20 44 ght (c) Rocket D
#   0x50: 69 76 69 73 69 6F 6E 20 53 6F 66 74 77 61 72 65 ivision Software
#   0x60: 20 32 30 30 33 2D 32 30 30 37 2E 20 41 6C 6C 20 2003-2007. All 
#   0x70: 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E rights reserved.
#   0x80: 0D 0A 0D 0A 0D 0A ...... 
# Or:
#   0x00: 1B 5B 32 4A 53 74 61 72 57 69 6E 64 20 41 6C 63 .[2JStarWind Alc
#   0x10: 6F 68 6F 6C 20 45 64 69 74 69 6F 6E 20 69 53 43 ohol Edition iSC
#   0x20: 53 49 20 54 61 72 67 65 74 20 76 33 2E 32 2E 33 SI Target v3.2.3
#   0x30: 20 28 42 75 69 6C 64 20 32 30 30 37 30 35 32 37 (Build 20070527
#   0x40: 2C 20 57 69 6E 33 32 2C 20 41 6C 63 6F 68 6F 6C , Win32, Alcohol
#   0x50: 20 45 64 69 74 69 6F 6E 29 0D 0A 43 6F 70 79 72 Edition)..Copyr
#   0x60: 69 67 68 74 20 28 63 29 20 52 6F 63 6B 65 74 20 ight (c) Rocket
#   0x70: 44 69 76 69 73 69 6F 6E 20 53 6F 66 74 77 61 72 Division Softwar
#   0x80: 65 20 32 30 30 33 2D 32 30 30 37 2E 20 41 6C 6C e 2003-2007. All
#   0x90: 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 rights reserved
#   0xA0: 2E 0D 0A 0D 0A 0D 0A .......

# More info: http://www.rocketdivision.com/wind.html
if (
  stridx(r0, '\x1b[2JStarWind ') == 0 &&
  '\r\nCopyright (c) Rocket Division Software' >< r0
)
{
  register_service(port:port, proto:"starwind_ctl");
  security_note(port:port, data:'The remote service is the control port for StarWind iSCSI Server.');
  exit(0);
}

# Submitted by Tom Van de Wiele 
#
# nb: these are possibly Witness ContactStore as OEM'd by Avaya.
if (
  "STNS:" >< r0 &&
  r0 =~ " TOKEN:[0-9]+:" && 
  r0 =~ "POOL:(meeting|ondemand|switch)\.assigned"
)
{
  register_service(port:port, proto:"avaya_slave_recorder");
  security_note(port:port, data:'An Avaya slave recorder is listening on this port.  It handles and\nlogs operational call data from various Avaya VoIP components.');
  exit(0);
}
# Spontaneous banner:
#   0x00: 31 20 50 49 4E 47 1B 1 PING. 
if (stridx(r0, '1 PING\x1b') == 0)
{
  register_service(port:port, proto:"avaya_monitor");
  security_note(port:port, data:'A service for monitoring Avaya VoIP components is listening on this\nport.');
  exit(0);
}

# LANDesk Targeted Multicast Service.
if (stridx(r0, 'TDMM\x1c\x00\x00\x00') == 0)
{
  register_service(port:port, proto:"landesk_tmcsvc");
  security_note(port:port, data:"LANDesk's Targeted Multicast service is listening on this port.");
  exit(0);
}

# ircd
#
# Spontaneous banner:
#   :irc.example.com NOTICE AUTH :*** Looking up your hostname...\r\n
#   :irc.example.com NOTICE AUTH :*** Checking Ident\r\n
#   :irc.example.com NOTICE AUTH :*** No Ident response\r\n
#   :irc.example.com NOTICE AUTH :*** Found your hostname\r\n
#
#   :irc.example.com NOTICE * :*** Looking up your hostname...\r\n
#   :irc.example.com NOTICE * :*** Found your hostname\r\n
if (
  (
    r0[0] == ':' && 
    (
      'NOTICE AUTH :*** Looking up your hostname...\r\n' >< r0 ||
      'NOTICE * :*** Looking up your hostname...\r\n' >< r0
    )
  ) ||
  stridx(r0, 'ERROR :Trying to reconnect too fast.\r\n') == 0 ||
  (
    stridx(r0, 'ERROR :Closing Link: [') == 0 &&
    "(Throttled: Reconnecting too fast)" >< r0
  )
)
{
  register_service(port:port, proto:"irc");
  security_note(port:port, data:"An IRC daemon is listening on this port.");
  exit(0);
}

# Jabber server
#
# Spontaneous banner:
#   <?xml version='1.0' encoding='utf-8'?><stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0" id="ID:example-1034-1202610100015-0:0" to="client" from="localhost"><stream:features xmlns:ns16="urn:ietf:params:xml:ns:xmpp-tls" xmlns:ns15="urn:ietf:params:xml:ns:xmpp-sasl" xmlns:ns14="http://jabber.org/protocol/muc#user" xmlns:ns13="http://jabber.org/protocol/muc" xmlns:ns12="http://jabber.org/protocol/disco#items" xmlns:ns11="http://jabber.org/protocol/disco#info" xmlns:ns10="urn:ietf:params:xml:ns:xmpp-streams" xmlns:ns9="jabber:server:dialback" xmlns:ns8="jabber:server" xmlns:ns7="jabber:iq:roster" xmlns:ns6="jabber:iq:auth" xmlns:ns5="jabber:iq:private" xmlns:ns4="urn:ietf:params:xml:ns:xmpp-stanzas"><ns15:mechanisms></ns15:mechanisms></stream:features>
#
# nb: see also xmpp_server_detect.nasl -- not all such servers produce
#     a spontaneous banner by sending an unsolicited stream tag.
if (
  "jabber:client" >< r0 &&
  "xmlns:stream=" >< r0 &&
  "from=" >< r0 &&
  "id=" >< r0
)
{
  # client connections
  register_service(port:port, proto:"jabber");
  security_note(port:port, data:"A Jabber server is listening on this port.
(client to server connections)");
  exit(0);
}

# Submitted by Olaf Brandt
#
# Spontaneous banner:
#   0x00: 00 00 00 AE 01 41 63 74 69 76 65 4D 51 00 00 00 .....ActiveMQ...
#   0x10: 03 01 00 00 00 9C 00 00 00 07 00 14 54 69 67 68 ............Tigh
#   0x20: 74 45 6E 63 6F 64 69 6E 67 45 6E 61 62 6C 65 64 tEncodingEnabled
#   0x30: 01 01 00 09 43 61 63 68 65 53 69 7A 65 05 00 00 ....CacheSize...
#   0x40: 04 00 00 11 54 63 70 4E 6F 44 65 6C 61 79 45 6E ....TcpNoDelayEn
#   0x50: 61 62 6C 65 64 01 01 00 12 53 69 7A 65 50 72 65 abled....SizePre
#   0x60: 66 69 78 44 69 73 61 62 6C 65 64 01 00 00 11 53 fixDisabled....S
#   0x70: 74 61 63 6B 54 72 61 63 65 45 6E 61 62 6C 65 64 tackTraceEnabled
#   0x80: 01 01 00 15 4D 61 78 49 6E 61 63 74 69 76 69 74 ....MaxInactivit
#   0x90: 79 44 75 72 61 74 69 6F 6E 06 00 00 00 00 00 00 yDuration.......
#   0xA0: 75 30 00 0C 43 61 63 68 65 45 6E 61 62 6C 65 64 u0..CacheEnabled
#   0xB0: 01 01 .. 
if (
  'ActiveMQ' >< r0 &&
  (
    'MaxInactivityDuration' >< r0 ||
    'StackTraceEnabled' >< r0 ||
    'TcpNoDelayEnabled' >< r0 ||
    'TightEncodingEnabled' >< r0
  )
)
{
  register_service(port:port, proto:"activemq");
  security_note(port:port, data:"An ActiveMQ OpenWire transport connector is listening on this port.");
  exit(0);
}

# Submitted by Tim Ashby
#
# Spontaneous banner:
#   Hello from GP-Version Server V7.1a
if (stridx(r0, 'Hello from GP-Version Server V') == 0)
{
  register_service(port:port, proto:"teamcoherence");
  security_note(port:port, data:'The remote service is a Team Coherence server, used for version control\nand issue tracking.');
  exit(0);
}

# Submitted by Thomas David Clarke.
#
# Spontaneous banner:
#   0x00: 5B B0 60 81 91 D3 9E 49 A2 2A 0F 99 FF 8A 5F 12 [.`....I.*...._.
#   0x10: 20 3B 18 FC DD 8D 8A 4E 85 43 24 88 11 35 F8 1F ;.....N.C$..5..
#   0x20: 01 00 .. 
if (stridx(r0, '\x5b\xb0\x60\x81\x91\xd3\x9e') == 0)
{
  register_service(port:port, proto:"agnitum_outpost");
  security_note(port:port, data:'The remote service appears to be Outpost Firewall.');
  exit(0);
}

# SupportWorks ITSM, http://www.hornbill.com/products/
#
# Submitted by John Soltys.
if (stridx(r0, "SW102: Hello[") == 0)
{
  register_service(port:port, proto:"swserverservice");
  security_note(port:port, data:'The remote service is the Supportworks main server, to which\nSupportworks clients connect.');
  exit(0);
}

# Dell Laser Printer.
#
# Submitted by Daniel Frazier.
if (stridx(r0, '\x00\x00\x00\x00Dell Laser Printer ') == 1)
{
  register_service(port:port, proto:"lexmark_raw");
  model = substr(r0, 5, r0_len - 2);
  security_note(port:port, data:'A ' + model + ' is listening on this port for raw\nconnections.');
  exit(0);
}

# GlobalSCAPE Secure FTP Admin Interface.
#
# Submitted by Rush Taggart.
if (
  stridx(r0, 'VRSN\x01\x00\x00\x00') == 8 && 
  stridx(r0, 'PTYP\x01\x00\x00\x00') == 0x14
)
{
  register_service(port:port, proto:"secure_ftp_admin");
  security_note(port:port, data:'The remote service is the administration interface for GlobalSCAPE\nSecure FTP Server.');
  exit(0);
}


# Battlefield Rcon, <http://bf2.fun-o-matic.org/index.php/RCon_Protocol>.
if (
  stridx(r0, '### Battlefield ') == 0 &&
  'RCON/admin' >< r0
)
{
  register_service(port:port, proto:"battlefield_rcon");
  security_note(port:port, data:'The remote service is a Battlefield RCON (Remote Console), used to\nadministrate the game server on the remote host.');
  exit(0);
}

# Lineage II, http://www.l2server.com/
#
# Submitted by Ky6uk.
if (
  r0_len == 0x52 &&
  stridx(r0, '\x52\x00\x6A\xB4\xAD\x52\x75\x5A\x74\x9B') == 0
)
{
  register_service(port:port, proto:"l2j_gameserver_login");
  security_note(port:port, data:'The remote service is the Game Server login port associated with the\ngame Lineage II.');
  exit(0);
}

# XB Media Streaming Protocol.
#
# Submitted by no way.
if (r0 =~ "^XBMSP-[0-9]+[0-9.]+[0-9] [0-9]+[0-9.]+[0-9] .+")
{
  register_service(port:port, proto:"xbmsp");
  server = r0;
  server = strstr(server, " ") - " ";
  server = strstr(server, " ") - " ";
  server = chomp(server);
  security_note(
    port:port, 
    data:string(
      "The remote service is an XBMSP (XB Media Streaming Protocol) server,\n",
      "identified by its banner as :\n",
      "\n",
      "  ", server
    )
  );
  exit(0);
}

# Verity K2 Search Server.
#
# Spontaneous banner:
#   02660@10.20.30.40:9920@[Uridium V1.0]@[K2 V6.00]@Encryption=None$1536
if ("]@[K2 V" >< r0 && "]@Encryption=" >< r0)
{
  register_service(port:port, proto:"verity_k2search");
  security_note(port:port, data:'A Verity K2 Search Server is running on this port.');
  exit(0);
}

# Verity K2 Index Server.
#
# Spontaneous banner:
#   02676@localhost:9960@[Uridium V1.0]@[K2Index V5.00]@Encryption=None$1536
if ("]@[K2Index V" >< r0 && "]@Encryption=" >< r0)
{
  register_service(port:port, proto:"verity_k2index");
  security_note(port:port, data:'A Verity K2 Index Server is running on this port.');
  exit(0);
}

# Blackboard Collaboration Server TCP/IP Port.
#
# Submitted by Tim McGuffin.
if ("blackboard.collab.lang.messaging.BaseMessage" >< r0)
{
  register_service(port:port, proto:"bb_collab_server_tcpip");
  security_note(port:port, data:'The remote service is the TCP/IP port for a Blackboard Collaboration\nServer.');
  exit(0);
}

# Kismet.
#
# Submitted by Anton Blaga.
if (stridx(r0, "*KISMET: ") == 0 && "*PROTOCOLS: " >< r0)
{
  register_service(port:port, proto:"kismet_server");
  security_note(port:port, data:'A Kismet Server is listening on the remote port.');
  exit(0);
}

# BMC Patrol Agent
#
# Submitted by G D Geen
if (stridx(r0, 'Who are you?\n\x00') == 6)
{
  register_service(port:port, proto:"bmcpatrolagent");
  security_note(port:port, data:'A BMC Patrol Agent is listening on this port.');
  exit(0);
}

# WinRemotePC agent
#
# nb: unicode version of "RPC rights".
if ('R\x00P\x00C\x00 \x00r\x00i\x00g\x00h\x00t\x00s' >< r0)
{
  register_service(port:port, proto:"wrpcserver");
  security_note(port:port, data:'A WinRemotePC Server is listening on this port.');
  exit(0);
}


# shroudBNC, http://www.shroudbnc.info/
#
# Submitted by Jeremy Finley.
if (
  ':Notice!notice@shroudbnc.org NOTICE * :*** shroudBNC' >< r0 ||
  ':shroudbnc.info NOTICE AUTH :*** shroudBNC' >< r0
)
{
  register_service(port:port, proto:"irc-bnc");
  security_note(port:port, data:'shroudBNC, an IRC proxy, is listening on this port.');
  exit(0);
}

# UC4 Executor, http://www.uc4.com/
#
# Submitted by Thomas Toth
if (
  'UC4:' >< r0 &&
  r0 =~ "^[0-9]+UC4:global[0-9]+NAT"
)
{
  register_service(port:port, proto:"uc4_executor");
  security_note(port:port, data:'A UC4.Executor agent for JMX is listening on this port.');
  exit(0);
}

# HP Printer
#
# Submitted by Tim Doty.
#
# nb: these banners can also be seen as responses to GET requests.
if (
  stridx(r0, '@PJL USTATUS TIMED\r\n') == 0 ||
  stridx(r0, '@PJL USTATUS DEVICE\r\n') == 0
)
{
  register_service(port:port, proto:"appsocket");
  security_note(port:port, data:'A Socket API service, commonly associated with print servers, is\nlistening on this port.');
  exit(0);
}

# Snare Agent, http://www.intersectalliance.com/projects/index.html
#
# Submitted by Paul Fitton.
if (r0 == '<HTML><BODY><CENTER>Authentication failed</CENTER></BODY></HTML>\r\n')
{
  register_service(port:port, proto:"www");
  # nb: it's broken because Nessus is not allowed to connect.
  set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
  security_note(
    port:port,
    data:string(
      "A Snare Agent remote control interface is listening on this port, and it\n",
      "is configured such that the Nessus server's IP address is not allowed\n",
      "to control it."
    )
  );
  exit(0);
}

# SAProuter
#
# Submitted by Peter Tijerina
if ('\x00SAProuter ' >< r0 || '\x00SAProuter ' >< r)
{
  register_service(port:port, proto:"saprouter");
  security_note(
    port:port, 
    data:string(
      "The remote service is a SAPRouter, a SAP program that acts as a\n",
      "network proxy between SAP Systems or between SAP Systems and external\n",
      "networks.\n"
    )
  );
  exit(0);
}

# CCProxy HTTP proxy
if (
  stridx(r0, "<h1>Unauthorized ...</h1>") == 0 &&
  "MAC Address: " >< r0 &&
  "Auth Result: Invalid user.</h2>" >< r0
)
{
  register_service(port:port, proto:"http_proxy");
  security_note(
    port:port, 
    data:string(
      "The remote service is a CCProxy HTTP proxy, and it is configured such\n",
      "that connections from the Nessus server's IP address are not allowed.\n"
    )
  );
  set_kb_item(name:"http_proxy/"+port+"/CCproxy", value:TRUE);
  exit(0);
}

# ChilliWorx
#
# Submitted by p.werner
if (stridx(r0, "ChilliSVC") == 0)
{
  register_service(port:port, proto:"chilliworx");
  security_note(port:port, data:'A ChilliWorx remote management agent is listening on this port.\n');
  exit(0);
}

# Scalix / Samsung Contact / OpenMail
#
# Submitted by Braam van Heerden
if ('\x02\x1c\x35\x30\x1c\x03\x00\x00\x00\x00' == r0)
{
  register_service(port:port, proto:"openmail_ual");
  security_note(
    port:port, 
    data:string(
      "A UAL (User Agent Layer) service is listening on this port.  It is part\n",
      "of a Scalix / Samsung Connect / OpenMail mail server and services\n",
      "connections from mail clients such as MS Outlook using a special plugin\n",
      "or an OpenMail GUI.\n"
    )
  );
  exit(0);
}

# Argus 
#
# Submitted by Joe Christy
if (
  stridx(r0, '\x80\x01') == 0 &&  
  stridx(r0, '\xE5\x61\x7A\xCB\x00\x00\x00\x00') == 8
)
{
  register_service(port:port, proto:"argus");
  security_note(port:port, data:'An Argus server is listening on this port.');
  exit(0);
}

# shroudBNC, http://www.shroudbnc.info/
#
# Submitted by Jeremy Finley.
if (r0[0] == ':' && 'NOTICE AUTH :BitlBee-IRCd ' >< r0)
{
  register_service(port:port, proto:"irc-bitlbee");
  security_note(
    port:port, 
    data:string(
      "BitlBee, an IRC daemon that acts as a gateway to instant messaging\n",
      "networks is listening on this port."
    )
  );
  exit(0);
}

# SSL / TLS Client Hello.
if (
  # TLSv1 / SSLv3.
  (
    r0_len >= 6 &&
    # message type (0x16 => handshake) + protocol version.
    (
      stridx(r0, '\x16\x03\x01') == 0 ||
      stridx(r0, '\x16\x03\x00') == 0
    ) && 
    ((ord(r0[3]) << 8 | ord(r0[4])) == r0_len - 5) &&
    # handshake type (1 => Client Hello).
    ord(r0[5]) == 1 &&
    # handshake version.
    (
      substr(r0, 9, 10) == '\x03\x01' ||
      substr(r0, 9, 10) == '\x03\x00' ||
      substr(r0, 9, 10) == '\x02\x00'
    )
  ) ||
  # SSLv2
  (
    r0_len >= 27 &&
    # message type (1 => Client Hello)
    ord(r0[2]) == 1 &&
    (((ord(r0[0]) ^ 0x80) << 8 | ord(r0[1])) == r0_len - 2) &&
    # handshake version
    (
      substr(r0, 3, 4) == '\x03\x01' ||
      substr(r0, 3, 4) == '\x03\x00' ||
      substr(r0, 3, 4) == '\x02\x00'
    )
  )
)
{
  local_var an, ssl_type;

  if (stridx(r0, '\x16\x03\x01') == 0) ssl_type = 'TLSv1';
  else if (stridx(r0, '\x16\x03\x00') == 0) ssl_type = 'SSLv3';
  else ssl_type = 'SSLv2';

  if (ssl_type == 'TLSv1') an = 'a';
  else an = 'an';

  register_service(port:port, proto:"ssl_client_"+tolower(ssl_type));
  security_note(
    port:port, 
    data:string(
      "The remote service sends ", an, " ", ssl_type, " Client Hello, which suggests it is some\n",
      "type of client expecting to connect to a server over an SSL-encrypted\n",
      "channel."
    )
  );
  exit(0);
}

# Fortinet Server Authentication Extension (FSAE) Collector Agent.
#
# Submitted by David Hocking.
if (
  "FSAE server 1." >< r0 &&
  r0_len == (ord(r0[3]) | ord(r0[2]) << 8 | ord(r0[1]) << 16 | ord(r0[0]) << 24)
)
{
  register_service(port:port, proto:"fortinet_fsae_ca");
  security_note(
    port:port, 
    data:string(
      "The remote service is an FSAE (Fortinet Server Authentication\n",
      "Extension) collector agent, which is installed on a Windows domain\n",
      "controller to send information about logins and group membership from\n",
      "DC agents to a FortiGate unit."
    )
  );
  exit(0);
}

# ManageSieve.
if (
  '"IMPLEMENTATION" "' >< r0 &&
  '"SIEVE" "' >< r0 &&
  '\r\nOK' >< r0
)
{
  register_service(port:port, proto:"managesieve");
  security_note(port:port, data:string("The remote service is a managesieve server."));
  exit(0);
}

# Unicenter Remote Control Agent.
#
# submitted by Lance Seelbach.
if (
  r0_len == 0x96 &&
  stridx(r0, '\x8D\x00\x00\x00\x8D\x00\x00\x00') == 0 &&
  stridx(r0, '\x02\x03\x01\x00\x01\x00') == 0x90
)
{
  register_service(port:port, proto:"ca_rchost");
  security_note(port:port, data:string("The remote service is a Unicenter Remote Control host agent."));
  exit(0);
}

# Pharos Notify, http://www.pharos.com/
#
# submitted by Andrew Jastremski.
if (
  stridx(r0, 'PSCOM') == 0 &&
  "AUTHENTICATE" >< r0
)
{
  register_service(port:port, proto:"pharos_notify");
  security_note(port:port, data:string("Pharos Notify appears to be listening on this port."));
  exit(0);
}

# UniGuard device, http://www.commdevices.com/products/encryption/uniguard.html
#
# submitted by Lane Burris 
if ("Communication Devices Inc. Network Interface, ver" >< r0)
{
  register_service(port:port, proto:"unigard");
  security_note(
    port:port, 
    data:string(
      "A UniGuard device, from Communication Devices Inc., appears to be\n",
      "listening on this port."
    )
  );
  exit(0);
}

# Citrix IMA
#
# submitted by Patrick Webster and Tim Russell.
if (
  r0_len > 4+18 &&
  r0_len == (ord(r0[0]) | ord(r0[1]) << 8 | ord(r0[2]) << 16 | ord(r0[3]) << 24) &&
  '\x81\x00\x00\x00' == substr(r0, 4, 7) &&
  '\x00\x00\x0C\x00\x01\x00\x00\x04\x0C\x00\x01\x00\x02\x00\x03\x00\x10\x00' == substr(r0, r0_len - 18)
)
{
  register_service(port:port, proto:"citrixima");
  security_note(
    port:port, 
    data:string(
      "A Citrix Independent Management Architecture (IMA) service appears to\n",
      "be listening on this port."
    )
  );
  exit(0);
}

if (r0 == '220\r\n')
{
  register_service(port:port, proto: "220backdoor");
  exit(0);
}

# Submitted by Natalie Green
# Port : 803
# 0x00: 5B B0 60 81 91 D3 9E 49 A2 2A 0F 99 FF 8A 5F 12 [.`....I.*...._.
# 0x10: 7F 1B C6 5F EE AE 09 43 AC 0D 43 D5 57 E5 17 57 ..._...C..C.W..W
# 0x20: 01 00 	       	     	      	       	     	..
# It seems that this banner changes at every connection.
if (r0 == '\x5B\xB0\x60\x81\x91\xD3\x9E\x49\xA2\x2A\x0F\x99\xFF\x8A\x5F\x12\x7F\x1B\xC6\x5F\xEE\xAE\x09\x43\xAC\x0D\x43\xD5\x57\xE5\x17\x57\x01\x00')
{
  register_service(port:port, proto: "outpost");
  security_note(port: port, data: "Agnitum's Outpost firewall is running on this port");
  exit(0);
}

# Submitted by Samuel Korpi
# Port : 544
# 0x00: 01 72 65 6D 73 68 64 3A 20 4B 65 72 62 65 72 6F .remshd: Kerbero
# 0x10: 73 20 41 75 74 68 65 6E 74 69 63 61 74 69 6F 6E s Authentication
# 0x20: 20 6E 6F 74 20 65 6E 61 62 6C 65 64 2E 0A        not enabled.. 
if (r0 == '\x01remshd: Kerberos Authentication not enabled.\n')
{
  register_service(port:port, proto: "kshell");
  security_note(port: port, data: 
"A Kerberized rsh service is running on this port. As Kerberos
authentication is not enabled, it cannot be used.");
  exit(0);
}

# Submitted by Cliff Nel
# Port : 2988
# Type : spontaneous
# 0x00: 4D 6F 6E 20 53 65 70 20 20 38 20 31 36 3A 32 31 Mon Sep 8 16:21
# 0x10: 3A 32 35 20 32 30 30 38 2C 20 57 61 72 6E 69 6E :25 2008, Warnin
# 0x20: 67 20 6F 6E 20 65 6E 63 72 79 70 74 69 6F 6E 20 g on encryption 
# 0x30: 6B 65 79 20 66 69 6C 65 20 60 2F 65 74 63 2F 61 key file `/etc/a
# 0x40: 66 62 61 63 6B 75 70 2F 63 72 79 70 74 6B 65 79 fbackup/cryptkey
# 0x50: 27 3A 20 46 69 6C 65 20 6E 6F 74 20 72 65 61 64 ': File not read
# 0x60: 61 62 6C 65 2E 0A 4D 6F 6E 20 53 65 70 20 20 38 able..Mon Sep 8
# 0x70: 20 31 36 3A 32 31 3A 32 35 20 32 30 30 38 2C 20  16:21:25 2008, 
# 0x80: 57 61 72 6E 69 6E 67 3A 20 49 67 6E 6F 72 69 6E Warning: Ignorin
# 0x90: 67 20 66 69 6C 65 20 60 2F 65 74 63 2F 61 66 62 g file `/etc/afb
# 0xA0: 61 63 6B 75 70 2F 63 72 79 70 74 6B 65 79 27 2C ackup/cryptkey',
# 0xB0: 20 75 73 69 6E 67 20 63 6F 6D 70 69 6C 65 64 2D using compiled-
# 0xC0: 69 6E 20 6B 65 79 2E 0A 61 66 62 61 63 6B 75 70 in key..afbackup
# 0xD0: 20 33 2E 34 0A 0A 41 46 27 73 20 62 61 63 6B 75  3.4..AF's backu
# 0xE0: 70 20 73 65 72 76 65 72 20 72 65 61 64 79 2E 0A p server ready..
#
# MA's configuration on Lab Manager
# 0x00:  61 66 62 61 63 6B 75 70 20 33 2E 34 0A 0A 41 46    afbackup 3.4..AF
# 0x10:  27 73 20 62 61 63 6B 75 70 20 73 65 72 76 65 72    's backup server
# 0x20:  20 72 65 61 64 79 2E 0A 68 F6 05 B4 1D 2E 5A 35     ready..h.....Z5
# 0x30:  81 CC 85 AD 1E 51 00 74                            .....Q.t        

if ('\n\nAF\'s backup server ready.\n' >< r0 &&
    egrep(string: r0, pattern: '^afbackup [1-9]\\.[0-9]+$'))
{
  register_service(port: port, proto: 'afbackup');
  security_note(port: port, data: 
"The remote service is the server component of AF's Backup System.");
  exit(0);
}

# Submitted by Matt Dalton
# Port : 1738
# Type : spontaneous
# 0x00: 48 45 4C 4C 4F 20 6C 69 73 74 65 6E 65 72 20 68 HELLO listener h
# 0x10: 61 6E 64 73 68 61 6B 65 20 76 31 20 62 75 69 6C andshake v1 buil
# 0x20: 64 3A 32 32 33 30 0A 50 52 4F 54 4F 43 4F 4C 20 d:2230.PROTOCOL
# 0x30: 72 73 61 5F 69 64 0A rsa_id.
# Description: Service: Peregrine Listener 6.0.1 (agtlsnr601) - Peregrine Systems, Inc. - C:\PROGRA~1\PEREGR~1\DESKTO~1\bin\iftlsnr.exe

if (match(string: r0, pattern: 'HELLO listener handshake v* build:*\nPROTOCOL *'))
{
  register_service(port: port, proto: 'peregrine-listener');
  security_note(port: port, data: 
"Peregrine Listener is running on this port.");
  exit(0);
}

# :R2C.BNC NOTICE AUTH :*** Welcome to R2C Bouncer.
# :R2C.BNC NOTICE AUTH :*** Please specify the BNC Password.
# :R2C.BNC NOTICE AUTH :*** Type "/pass <password>" to login.

if (match(string: r0, pattern: ":R2C.BNC NOTICE AUTH :*"))
{
  register_service(port: port, proto: 'irc-bnc');
  security_note(port: port, data: 
"An IRC bouncer is running on this port.");
  exit(0);
}

# ICSP master.
#
# Submitted by Patrick Webster
if ('\x00NI Master\x00AMX Corp.' >< r0)
{
  register_service(port: port, proto: 'panja-icsp');
  security_note(
    port:port, 
    data:string(
      "An ICSP (Internet Control System Protocol) service is listening on the\n",
      "remote port.  ICSP is a peer-to-peer protocol used in Master-to-Master\n",
      "and Master-to-device communications by AMX NetLinx Integrated\n",
      "Controllers for advanced control and automation of areas and rooms."
    )
  );
  exit(0);
}

# Parallels dispatcher service.
#
# Submitted by Paul Stinson.
if (
  stridx(r0, 'PRLT') == 0 &&
  ereg(pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]", string:substr(r0, 8))
)
{
  local_var v;

  v = eregmatch(pattern:"^([0-9]+)\.([0-9]+)\.([0-9]+)\.[0-9]", string:substr(r0, 8));

  register_service(port: port, proto: 'prl_disp_service');
  security_note(
    port:port, 
    data:string(
      "A Parallels dispatcher service is listening on the remote port.  It\n",
      "identifies itself as version ", v[1], ".", v[2], " Build ", v[3], "."
    )
  );
  exit(0);
}

if (substr_at_offset(str:r0, blob:"Asterisk Call Manager/", offset:0))
{
  register_service(port: port, proto:'asterisk');
  security_note(port:port, data:"An Asterisk Call Manager service is running on this port.");
  exit(0);
}

# AOL / OSCAR
#
# nb: the spontaneous banner is a FLAC SIGNON frame - see 
#     <http://dev.aol.com/aim/oscar/>.
#
# Submitted by Joseph Bruni.
if (
  strlen(r0) == 10 &&
  substr_at_offset(str:r0, blob:'*\x01', offset:0) &&
  substr_at_offset(str:r0, blob:'\x00\x04\x00\x00\x00\x01', offset:4)
)
{
  register_service(port: port, proto: 'aol');
  security_note(
    port:port, 
    data:string(
      "An instant messaging server is listening on this port.  It speaks the\n",
      "OSCAR (Open System for Communication in Realtime) protocol, which is\n",
      "used by AOL's ICQ and AIM messaging systems as well as services that\n",
      "proxy connections to those systems."
    )
  );
  exit(0);
}

# UI-View local APRS Server, http://www.ui-view.org/
#
# Submitted by Tim Doty.
if (
  substr_at_offset(str:r0, blob:'UI-View ', offset:0) &&
  ' APRS Server' >< r0
)
{
  register_service(port: port, proto: 'ui_view_local_aprs');
  security_note(
    port:port, 
    data:string(
      "The remote service is a local APRS (Automatic Packet Reporting System)\n",
      "server enabled as part of UI-View, a Windows program used by amateur\n",
      "radio operators.  It is intended to allow other APRS systems on the\n",
      "network to connect to it as client and send and receive data.  Here is\n",
      "its banner :\n",
      "\n",
      "  ", r0
    )
  );
  exit(0);
}

# The banner is emitted again every 10 (?) seconds.
# 0x00: 00 58 08 00 7D 08 0D 0A 00 2E 08 50 6C 65 61 73 .X..}......Pleas
# 0x10: 65 20 70 72 65 73 73 20 3C 45 6E 74 65 72 3E 2E e press <Enter>.
# 0x20: 2E 2E 0D 0A 00 58 08 00 7D 08 0D 0A 00 2E 08 50 .....X..}......P
# 0x30: 6C 65 61 73 65 20 70 72 65 73 73 20 3C 45 6E 74 lease press <Ent
# 0x40: 65 72 3E 2E 2E 2E 0D 0A er>.....
#
# Contrib:
# 0x00: 00 58 08 00 7D 08 0D 0A 00 2E 08 C7 EB B0 B4 20 .X..}.......... 
# 0x10: 3C 45 6E 74 65 72 3E 2E 2E 2E 0D 0A <Enter>.....

if (substr_at_offset(str:r0, offset:0, blob: '\x00X\x08\x00\x7d\x08\x0d\x0a\x00\x2e\x08Please press <Enter>...') ||
    substr_at_offset(str:r0, offset:0, blob: '\x00X\x08\x00\x7d\x08\x0d\x0a\x00\x2e\x08\xc7\xeb\xb0\xb4 <Enter>...') )
{
  register_service(port: port, proto: 'pcanywheredata');
  security_note(port: port, data: 'pcAnywhere is running on this port.\n');
  exit(0);
}

# XC2 2005
#
# Submitted by Kevin Kasner
if (
  # packet length
  ord(r0[0]) == 0 && ord(r0[1]) == 0 && ord(r0[2]) == 0 && ord(r0[3]) == r0_len &&
  substr_at_offset(str:r0, blob:'\x0bXC2_2K5.4DC', offset:8)
)
{
  register_service(port: port, proto: 'xc2_server');
  security_note(
    port:port, 
    data:string(
      "XC2 Server Application is listening on this port.  It is the server\n",
      "component used by XC2 Software, an administrative software for cross\n",
      "connection control management used by water and wastewater utilities\n",
      "and service organizations."
    )
  );
  exit(0);
}

# issDaemon
#
# Submitted by Yarick Tsagoyko, Chad Holmes, and Jean-Pierre Denis
if (
  ord(r0[0]) == 0 && ord(r0[1]) == 0 && ord(r0[2]) == 0 && (ord(r0[3]) + 4) == r0_len &&
  substr_at_offset(str:r0, blob:'\x08\x01\x04\x01', offset:4) &&
  ord(r0[8]) == 0 && (ord(r0[9]) + 8 + 4) == r0_len &&
  substr_at_offset(str:r0, blob:'\xa4\x00\x00\x00\x66\x03\x00\x00\x80\x04\x06\x00\x00\xa8\x00\xa0\x00\x00\xff\xff', offset:r0_len-20)
)
{
  register_service(port: port, proto: 'issdaemon');
  security_note(
    port:port, 
    data:string(
      "An ISS Daemon (issDaemon) service is listening on this port.  It is\n",
      "used to handle command and control connections by various products\n",
      "from IBM Internet Security Systems (ISS) such as Proventia Server\n",
      "Protection, RealSecure Sensor Server, RealSecure Network Sensor, and\n",
      "SiteProtector."
    )
  );
  exit(0);
}

# Bartlby Agent, http://www.bartlby.org/
#
# Submitted by Helmut Januschka.
if (
  substr_at_offset(str:r0, blob:"OS: ", offset:0) &&
  ereg(pattern:"^OS: (Linux|windows\.NET) V: [0-9][.0-9]+", string:r0)
)
{
  register_service(port: port, proto: 'bartlby');
  security_note(
    port:port, 
    data:
"A Bartlby Agent is listening on the remote host.  Bartlby is a
network and systems monitor, and the agent runs on individual Linux,
Windows, or Mac computers to collect information to be reported
through Bartlby's central, web-based user interface."
  );
  exit(0);
}

# Deliantra game server, http://www.deliantra.net/
#
# 0x00:  00 23 76 65 72 73 69 6F 6E 20 31 30 32 33 20 31    .#version 1023 1
# 0x10:  30 32 36 20 44 65 6C 69 61 6E 74 72 61 20 53 65    026 Deliantra Se
# 0x20:  72 76 65 72 0A                                     rver.           
if (
  'Deliantra Server' >< r0 &&
  ereg(pattern:"#version [0-9]+ [0-9]+ Deliantra Server", string:r0)
)
{
  register_service(port: port, proto: 'deliantra');
  security_note(
    port:port, 
    data:"A Deliantra game server is listening on this port."
  );
  exit(0);
}

# lsoft Technologies DiskMonitorFree
# This service prints a line of 18 hexadecimal digits every time LF is sent.
# The GET banner would be longer and the consistency test would fail.
if (is_lsof_diskmonitor(banner: r0))
{
  register_service(port: port, proto: 'lsoft_diskmonitor');
  security_note(port:port, 
    data:"Lsoft Technologies DiskMonitor is listening on this port.");
  exit(0);
}


#
# Keep qotd at the end of the list, as it may generate false detection
# 

# This former regex won't match non ASCII characters in the author's name
# r0 =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$')

if (r0 =~ '^"[^"]+"[ \t\r\n]+[^+*@(){}\\\\/@0-9_]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$')
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd seems to be running on this port");
  exit(0);
}
# Keep qotd at the of the list!
}	# else: no spontaneous banner

###################################################
######## Updates for answers to GET / ...  ########
###################################################

k = 'FindService/tcp/'+port+'/get_http';
r = get_kb_item(k+'Hex');
if (strlen(r) > 0) r = hex2raw(s: r);
else r = get_kb_item(k);

r_len = strlen(r);
if (r_len == 0)
{
 if (get_sent			# Service did not anwer to GET
     && ! thorough_tests)	# We try again in "thorough tests"
  exit(0);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
 r = recv(socket:soc, length:4096);
 close(soc);
 r_len = strlen(r);
 if (r_len == 0)
 {
   debug_print('Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n');
   exit(0);
 }
 set_kb_item(name: k, value: r);
 if ('\0' >< r) set_kb_item(name: k + 'Hex', value: hexstr(r));
}

# aka HTTP/0.9
if (r =~ '^[ \t\r\n]*<HTML>.*</HTML>' ||
# In case of truncated answer
    r=~ '^[ \t\r\n]*<HTML>[ \t\r\n]*<HEAD>.*</HEAD>[ \t\r\n]*<BODY( +[^>]+)?>')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0);
}

if (match(string: r, pattern: "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' xmlns:db='jabber:server:dialback' id='*'><stream:error><xml-not-well-formed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>"))
{
 # Server connections
 register_service(port:port, proto:"jabber_s2s");
 security_note(port:port, data:"A Jabber server is listening on this port.
(server to server connections)");
  exit(0);
}

# Also seen in response to GET /
if (  "jabber:client" >< r && "xmlns:stream=" >< r &&
  "from=" >< r &&  "id=" >< r )
{
  # client connections
  register_service(port:port, proto:"jabber");
  security_note(port:port, data:"A Jabber server is listening on this port.
(client to server connections)");
  exit(0);
}

# Teamspeak, http://teamspeak.com/
if (
  r == '[TS]\r\n' ||
  r == '[TS]\r\nerror\r\n'
)
{
 register_service(port:port, proto:'teamspeak-tcpquery');
 security_note(port:port, data:"A TeamSpeak TCPQUERY server is listening on the remote host");
 exit(0);
}

# gpsd (tcp/2947)
if (r == 'GPSD,G=?,E=?,T=?,T=?,T=?,P=?')
{
  register_service(port: port, proto: "gpsd");
  security_note(port: port, data: "gpsd is running on this port");
  exit(0);
}

# Veritas Backup Exec Remote Agent (6103/tcp)
if (r == '\xF6\xFF\xFF\xFF\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' )
{
  register_service(port: port, proto: "backup_exec");
  security_note(port: port, data: "Veritas Backup Exec Remote Agent is running on this port");
  exit(0);
}

if (r == 'gethostbyaddr: Error 0\n')
{
 register_service(port:port, proto:"veritas-netbackup-client");
 security_note(port:port, data:"Veritas NetBackup Client Service is running on this port");
 exit(0);
}

if ("GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r)
{
 report_service(port: port, svc: 'auth', banner: r);
 exit(0);
}

if ('Host' >< r && 'is not allowed to connect to this MySQL server' >< r)
{
 register_service(port: port, proto: 'mysql');	# or wrapped?
 set_kb_item(name: 'mysql/blocked/'+port, value: TRUE);
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but it rejects
connections from the Nessus scanner.");
  exit(0);
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if ('Host' >< r && ' is blocked ' >< r && 'mysqladmin flush-hosts' >< r)
{
 register_service(port: port, proto: 'mysql');
 # set_kb_item(name: 'mysql/blocked/'+port, value: TRUE);
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but the 
Nessus scanner IP has been blacklisted.
Run 'mysqladmin flush-hosts' if you want complete tests.");
  exit(0);
}

# See http://www.varnish-cache.org/
# 101 32
# all commands are in lower-case.
# (the first number appears to be a code, e.g. 200 for OK; the 2nd is the 
# length of the answer)
if (match(string: r, pattern: '101 *\nall commands are in lower-case.\n*'))
{
  register_service(port: port, proto: 'varnish_mngt');
  security_note(port: port, data: "Varnish Management is running on this port.");
  exit(0);
}

if ( "Asterisk Call Manager" >< r )
{
 register_service(port: port, proto: 'asterisk');
 security_note(port: port, data: "An Asterisk Call Manager server is running on this port.");
  exit(0);
}

# Keep this before MSDTC!
if (r == '\x70\x63\x70\x00\x00\x02')
{
  register_service(port: port, proto: 'ekpd');
 security_note(port: port, data: 
"EKPD, a component of Seiko Epson Color Inkjet printing driver for Linux, 
is running on this port.");
  exit(0);
}


# Taken from find_service2 (obsolete, as the string contains a \0)
if (r_len == 3 && (r[2] == '\x10'||	# same test as find_service
                   r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "An MSDTC server seems to be running on this port");
  exit(0);
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 .. 
# 00: F8 2D 0B 00 00 16 .-.... 
if ((r_len == 5 || r_len == 6) && r[3] == '\0' && 
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0')
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "An MSDTC server seems to be running on this port");
  exit(0);
}

if (
  r == '\x01Permission denied' || 
  (
    "lpd " >< r && 
    (
      "connected from invalid port" >< r ||
      "Print-services" >< r
    )
  )
)
{
  register_service(port:port, proto:'lpd');
  security_note(port: port, data: 'An LPD server is running on this port');
  exit(0);
}

# On port 264 - submitted by Jeff Healy
if (r == '\x59\x00\x00\x00' && port == 264)
{
 register_service(port:port, proto:'fw1-topology-download');
 security_note(port: port, data: 'Check Point FireWall-1 checkpoint topology download is running on this port');
 exit(0);
}

# Submitted by Shiva Subramanian
#
# nb: default port is TCP 8891.
if (
  r_len > 96 &&
  substr(r, 0, 3) == "PKGP" && 
  substr(r, 4, 23) =~ "^[0-9a-fA-F]+$"
)
{
  register_service(port:port, proto:"seagent");
  security_note(port:port, data:"CA Access Control's seagent seems to be listening on this port.");
  exit(0);
}

# from Universal IRC daemon when throttling connections.
#   "ERROR :Closing Link: [192.168.100.90] by lab.UnderNet.org (Your host is trying to (re)connect too fast -- throttled)"
if ("ERROR :Closing Link: [" >< r && "throttled" >< r)
{
  register_service(port:port, proto:'irc');
  security_note(
    port:port, 
    data:'An IRC server is running on this port and throttling connections from\nthe Nessus server.'
  );
 exit(0);
}

# Submitted by Ky6uk.
if (stridx(r, string("You are not authorized (", this_host(), ")\r\n<br>\r\n<a href=")) == 0)
{
 register_service(port:port, proto:"http_proxy");
 security_note(port:port, data:'An HTTP proxy from UserGate is listening on this port and blocking\nconnections from the Nessus server\'s IP.');

 exit(0);
}

# Submitted by Kimmo Torkkeli
if (
  stridx(r, "* OK SSP MagniComp SysInfo Server") == 0 ||
  stridx(r, "*-OK SSP MagniComp SysInfo Server") == 0
)
{
 register_service(port:port, proto:"mcsysinfod");
 security_note(port:port, data:'A MagniComp SysInfo agent is listening on this port.');

 exit(0);
}

# on port 6085. Submitted by Kevin Smith
# 
# 0x0000: 4A 4E 42 33 30 0E 03 00 00 FF F0 00 01 0A 00 34 JNB30..........4
# 0x0010: 00 00 00 00 49 00 6E 00 76 00 61 00 6C 00 69 00 ....I.n.v.a.l.i.
# 0x0020: 64 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 d. .r.e.q.u.e.s.
# 0x0030: 74 00 3A 00 20 00 20 00 69 00 6E 00 76 00 61 00 t.:. . .i.n.v.a.
# 0x0040: 6C 00 69 00 64 00 20 00 6A 00 6E 00 62 00 62 00 l.i.d. .j.n.b.b.
# 0x0050: 69 00 6E 00 61 00 72 00 79 00 20 00 6D 00 65 00 i.n.a.r.y. .m.e.
# 0x0060: 73 00 73 00 61 00 67 00 65 00 20 00 70 00 72 00 s.s.a.g.e..p.r.
# 0x0070: 65 00 61 00 6D 00 62 00 6C 00 65 0A 00 4A 01 00 e.a.m.b.l.e..J..
# 0x0080: 00 00 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 62 00 ..c.o.m...j.n.b.
# 0x0090: 72 00 69 00 64 00 67 00 65 00 2E 00 6A 00 6E 00 r.i.d.g.e...j.n.
# 0x00A0: 62 00 63 00 6F 00 72 00 65 00 2E 00 73 00 65 00 b.c.o.r.e...s.e.
# 0x00B0: 72 00 76 00 65 00 72 00 2E 00 62 00 2E 00 61 00 r.v.e.r...b...a.
# 0x00C0: 3A 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 :. .i.n.v.a.l.i.
# 0x00D0: 64 00 20 00 6A 00 6E 00 62 00 62 00 69 00 6E 00 d. .j.n.b.b.i.n.
# 0x00E0: 61 00 72 00 79 00 20 00 6D 00 65 00 73 00 73 00 a.r.y. .m.e.s.s.
# 0x00F0: 61 00 67 00 65 00 20 00 70 00 72 00 65 00 61 00 a.g.e. .p.r.e.a.
# 0x0100: 6D 00 62 00 6C 00 65 00 0D 00 0A 00 09 00 61 00 m.b.l.e.......a.
# 0x0110: 74 00 20 00 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 t. .c.o.m...j.n.
# 0x0120: 62 00 72 00 69 00 64 00 67 00 65 00 2E 00 6A 00 b.r.i.d.g.e...j.
# 0x0130: 6E 00 62 00 63 00 6F 00 72 00 65 00 2E 00 64 00 n.b.c.o.r.e...d.
# 0x0140: 2E 00 63 00 2E 00 6E 00 75 00 6C 00 6C 00 28 00 ..c...n.u.l.l.(.
# 0x0150: 55 00 6E 00 6B 00 6E 00 6F 00 77 00 6E 00 20 00 U.n.k.n.o.w.n. .
# 0x0160: 53 00 6F 00 75 00 72 00 63 00 65 00 29 00 0D 00 S.o.u.r.c.e.)...
# 0x0170: 0A 00 09 00 61 00 74 00 20 00 63 00 6F 00 6D 00 ....a.t. .c.o.m.
# 0x0180: 2E 00 6A 00 6E 00 62 00 72 00 69 00 64 00 67 00 ..j.n.b.r.i.d.g.
# 0x0190: 65 00 2E 00 6A 00 6E 00 62 00 63 00 6F 00 72 00 e...j.n.b.c.o.r.
# 0x01A0: 65 00 2E 00 73 00 65 00 72 00 76 00 65 00 72 00 e...s.e.r.v.e.r.
# 0x01B0: 2E 00 62 00 2E 00 64 00 2E 00 61 00 28 00 55 00 ..b...d...a.(.U.
# 0x01C0: 6E 00 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 n.k.n.o.w.n. .S.
# 0x01D0: 6F 00 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 o.u.r.c.e.).....
# 0x01E0: 09 00 61 00 74 00 20 00 63 00 6F 00 6D 00 2E 00 ..a.t. .c.o.m...
# 0x01F0: 6A 00 6E 00 62 00 72 00 69 00 64 00 67 00 65 00 j.n.b.r.i.d.g.e.
# 0x0200: 2E 00 6A 00 6E 00 62 00 63 00 6F 00 72 00 65 00 ..j.n.b.c.o.r.e.
# 0x0210: 2E 00 73 00 65 00 72 00 76 00 65 00 72 00 2E 00 ..s.e.r.v.e.r...
# 0x0220: 62 00 2E 00 63 00 2E 00 6F 00 28 00 55 00 6E 00 b...c...o.(.U.n.
# 0x0230: 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 6F 00 k.n.o.w.n. .S.o.
# 0x0240: 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 09 00 u.r.c.e.).......
# 0x0250: 61 00 74 00 20 00 63 00 6F 00 6D 00 2E 00 6A 00 a.t. .c.o.m...j.
# 0x0260: 6E 00 62 00 72 00 69 00 64 00 67 00 65 00 2E 00 n.b.r.i.d.g.e...
# 0x0270: 6A 00 6E 00 62 00 63 00 6F 00 72 00 65 00 2E 00 j.n.b.c.o.r.e...
# 0x0280: 73 00 65 00 72 00 76 00 65 00 72 00 2E 00 62 00 s.e.r.v.e.r...b.
# 0x0290: 2E 00 63 00 2E 00 72 00 75 00 6E 00 28 00 55 00 ..c...r.u.n.(.U.
# 0x02A0: 6E 00 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 n.k.n.o.w.n. .S.
# 0x02B0: 6F 00 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 o.u.r.c.e.).....
# 0x02C0: 09 00 61 00 74 00 20 00 6A 00 61 00 76 00 61 00 ..a.t. .j.a.v.a.
# 0x02D0: 2E 00 6C 00 61 00 6E 00 67 00 2E 00 54 00 68 00 ..l.a.n.g...T.h.
# 0x02E0: 72 00 65 00 61 00 64 00 2E 00 72 00 75 00 6E 00 r.e.a.d...r.u.n.
# 0x02F0: 28 00 54 00 68 00 72 00 65 00 61 00 64 00 2E 00 (.T.h.r.e.a.d...
# 0x0300: 6A 00 61 00 76 00 61 00 3A 00 36 00 31 00 39 00 j.a.v.a.:.6.1.9.
# 0x0310: 29 00 0D 00 0A C0 00 4A 4E 42 33 30 0E 03 00 00 )......JNB30....
# 0x0320: FF F0 00 01 0A 00 34 00 00 00 00 49 00 6E 00 76 ......4....I.n.v
# 0x0330: 00 61 00 6C 00 69 00 64 00 20 00 72 00 65 00 71 .a.l.i.d. .r.e.q
# 0x0340: 00 75 00 65 00 73 00 74 00 3A 00 20 00 20 00 69 .u.e.s.t.:. . .i
# 0x0350: 00 6E 00 76 00 61 00 6C 00 69 00 64 00 20 00 6A .n.v.a.l.i.d. .j
# 0x0360: 00 6E 00 62 00 62 00 69 00 6E 00 61 00 72 00 79 .n.b.b.i.n.a.r.y
# 0x0370: 00 20 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 . .m.e.s.s.a.g.e
# 0x0380: 00 20 00 70 00 72 00 65 00 61 00 6D 00 62 00 6C . .p.r.e.a.m.b.l
# 0x0390: 00 65 0A 00 4A 01 00 00 00 63 00 6F 00 6D 00 2E .e..J....c.o.m..
# 0x03A0: 00 6A 00 6E 00 62 00 72 00 69 00 64 00 67 00 65 .j.n.b.r.i.d.g.e
# 0x03B0: 00 2E 00 6A 00 6E 00 62 00 63 00 6F 00 72 00 65 ...j.n.b.c.o.r.e
# 0x03C0: 00 2E 00 73 00 65 00 72 00 76 00 65 00 72 00 2E ...s.e.r.v.e.r..
# 0x03D0: 00 62 00 2E 00 61 00 3A 00 20 00 69 00 6E 00 76 .b...a.:. .i.n.v
# 0x03E0: 00 61 00 6C 00 69 00 64 00 20 00 6A 00 6E 00 62 .a.l.i.d. .j.n.b
# 0x03F0: 00 62 00 69 00 6E 00 61 00 72 00 79 00 20 00 6D .b.i.n.a.r.y. .m
# 0x0400: 00 65 00 73 00 73 00 61 00 67 00 65 00 20 00 70 .e.s.s.a.g.e. .p
# 0x0410: 00 72 00 65 00 61 00 6D 00 62 00 6C 00 65 00 0D .r.e.a.m.b.l.e..
# 0x0420: 00 0A 00 09 00 61 00 74 00 20 00 63 00 6F 00 6D .....a.t. .c.o.m
# 0x0430: 00 2E 00 6A 00 6E 00 62 00 72 00 69 00 64 00 67 ...j.n.b.r.i.d.g
# 0x0440: 00 65 00 2E 00 6A 00 6E 00 62 00 63 00 6F 00 72 .e...j.n.b.c.o.r
# 0x0450: 00 65 00 2E 00 64 00 2E 00 63 00 2E 00 6E 00 75 .e...d...c...n.u
# 0x0460: 00 6C 00 6C 00 28 00 55 00 6E 00 6B 00 6E 00 6F .l.l.(.U.n.k.n.o
# 0x0470: 00 77 00 6E 00 20 00 53 00 6F 00 75 00 72 00 63 .w.n. .S.o.u.r.c
# 0x0480: 00 65 00 29 00 0D 00 0A 00 09 00 61 00 74 00 20 .e.).......a.t.
# 0x0490: 00 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 62 00 72 .c.o.m...j.n.b.r
# 0x04A0: 00 69 00 64 00 67 00 65 00 2E 00 6A 00 6E 00 62 .i.d.g.e...j.n.b
# 0x04B0: 00 63 00 6F 00 72 00 65 00 2E 00 73 00 65 00 72 .c.o.r.e...s.e.r
# 0x04C0: 00 76 00 65 00 72 00 2E 00 62 00 2E 00 64 00 2E .v.e.r...b...d..
# 0x04D0: 00 61 00 28 00 55 00 6E 00 6B 00 6E 00 6F 00 77 .a.(.U.n.k.n.o.w
# 0x04E0: 00 6E 00 20 00 53 00 6F 00 75 00 72 00 63 00 65 .n. .S.o.u.r.c.e
# 0x04F0: 00 29 00 0D 00 0A 00 09 00 61 00 74 00 20 00 63 .).......a.t. .c
# 0x0500: 00 6F 00 6D 00 2E 00 6A 00 6E 00 62 00 72 00 69 .o.m...j.n.b.r.i
# 0x0510: 00 64 00 67 00 65 00 2E 00 6A 00 6E 00 62 00 63 .d.g.e...j.n.b.c
# 0x0520: 00 6F 00 72 00 65 00 2E 00 73 00 65 00 72 00 76 .o.r.e...s.e.r.v
# 0x0530: 00 65 00 72 00 2E 00 62 00 2E 00 63 00 2E 00 6F .e.r...b...c...o
# 0x0540: 00 28 00 55 00 6E 00 6B 00 6E 00 6F 00 77 00 6E .(.U.n.k.n.o.w.n
# 0x0550: 00 20 00 53 00 6F 00 75 00 72 00 63 00 65 00 29 . .S.o.u.r.c.e.)
# 0x0560: 00 0D 00 0A 00 09 00 61 00 74 00 20 00 63 00 6F .......a.t. .c.o
# 0x0570: 00 6D 00 2E 00 6A 00 6E 00 62 00 72 00 69 00 64 .m...j.n.b.r.i.d
# 0x0580: 00 67 00 65 00 2E 00 6A 00 6E 00 62 00 63 00 6F .g.e...j.n.b.c.o
# 0x0590: 00 72 00 65 00 2E 00 73 00 65 00 72 00 76 00 65 .r.e...s.e.r.v.e
# 0x05A0: 00 72 00 2E 00 62 00 2E 00 63 00 2E 00 72 00 75 .r...b...c...r.u
# 0x05B0: 00 6E 00 28 00 55 00 6E 00 6B 00 6E 00 6F 00 77 .n.(.U.n.k.n.o.w
# 0x05C0: 00 6E 00 20 00 53 00 6F 00 75 00 72 00 63 00 65 .n. .S.o.u.r.c.e
# 0x05D0: 00 29 00 0D 00 0A 00 09 00 61 00 74 00 20 00 6A .).......a.t. .j
# 0x05E0: 00 61 00 76 00 61 00 2E 00 6C 00 61 00 6E 00 67 .a.v.a...l.a.n.g
# 0x05F0: 00 2E 00 54 00 68 00 72 00 65 00 61 00 64 00 2E ...T.h.r.e.a.d..
# 0x0600: 00 72 00 75 00 6E 00 28 00 54 00 68 00 72 00 65 .r.u.n.(.T.h.r.e
# 0x0610: 00 61 00 64 00 2E 00 6A 00 61 00 76 00 61 00 3A .a.d...j.a.v.a.:
# 0x0620: 00 36 00 31 00 39 00 29 00 0D 00 0A C0 00 4A 4E .6.1.9.)......JN
# 0x0630: 42 33 30 0E 03 00 00 FF F0 00 01 0A 00 34 00 00 B30..........4..
# 0x0640: 00 00 49 00 6E 00 76 00 61 00 6C 00 69 00 64 00 ..I.n.v.a.l.i.d.
# 0x0650: 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 .r.e.q.u.e.s.t.
# 0x0660: 3A 00 20 00 20 00 69 00 6E 00 76 00 61 00 6C 00 :. . .i.n.v.a.l.
# 0x0670: 69 00 64 00 20 00 6A 00 6E 00 62 00 62 00 69 00 i.d. .j.n.b.b.i.
# 0x0680: 6E 00 61 00 72 00 79 00 20 00 6D 00 65 00 73 00 n.a.r.y. .m.e.s.
# 0x0690: 73 00 61 00 67 00 65 00 20 00 70 00 72 00 65 00 s.a.g.e. .p.r.e.
# 0x06A0: 61 00 6D 00 62 00 6C 00 65 0A 00 4A 01 00 00 00 a.m.b.l.e..J....
# 0x06B0: 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 62 00 72 00 c.o.m...j.n.b.r.
# 0x06C0: 69 00 64 00 67 00 65 00 2E 00 6A 00 6E 00 62 00 i.d.g.e...j.n.b.
# 0x06D0: 63 00 6F 00 72 00 65 00 2E 00 73 00 65 00 72 00 c.o.r.e...s.e.r.
# 0x06E0: 76 00 65 00 72 00 2E 00 62 00 2E 00 61 00 3A 00 v.e.r...b...a.:.
# 0x06F0: 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 .i.n.v.a.l.i.d.
# 0x0700: 20 00 6A 00 6E 00 62 00 62 00 69 00 6E 00 61 00 .j.n.b.b.i.n.a.
# 0x0710: 72 00 79 00 20 00 6D 00 65 00 73 00 73 00 61 00 r.y. .m.e.s.s.a.
# 0x0720: 67 00 65 00 20 00 70 00 72 00 65 00 61 00 6D 00 g.e. .p.r.e.a.m.
# 0x0730: 62 00 6C 00 65 00 0D 00 0A 00 09 00 61 00 74 00 b.l.e.......a.t.
# 0x0740: 20 00 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 62 00 .c.o.m...j.n.b.
# 0x0750: 72 00 69 00 64 00 67 00 65 00 2E 00 6A 00 6E 00 r.i.d.g.e...j.n.
# 0x0760: 62 00 63 00 6F 00 72 00 65 00 2E 00 64 00 2E 00 b.c.o.r.e...d...
# 0x0770: 63 00 2E 00 6E 00 75 00 6C 00 6C 00 28 00 55 00 c...n.u.l.l.(.U.
# 0x0780: 6E 00 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 n.k.n.o.w.n. .S.
# 0x0790: 6F 00 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 o.u.r.c.e.).....
# 0x07A0: 09 00 61 00 74 00 20 00 63 00 6F 00 6D 00 2E 00 ..a.t. .c.o.m...
# 0x07B0: 6A 00 6E 00 62 00 72 00 69 00 64 00 67 00 65 00 j.n.b.r.i.d.g.e.
# 0x07C0: 2E 00 6A 00 6E 00 62 00 63 00 6F 00 72 00 65 00 ..j.n.b.c.o.r.e.
# 0x07D0: 2E 00 73 00 65 00 72 00 76 00 65 00 72 00 2E 00 ..s.e.r.v.e.r...
# 0x07E0: 62 00 2E 00 64 00 2E 00 61 00 28 00 55 00 6E 00 b...d...a.(.U.n.
# 0x07F0: 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 6F 00 k.n.o.w.n. .S.o.
# 0x0800: 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 09 00 u.r.c.e.).......
# 0x0810: 61 00 74 00 20 00 63 00 6F 00 6D 00 2E 00 6A 00 a.t. .c.o.m...j.
# 0x0820: 6E 00 62 00 72 00 69 00 64 00 67 00 65 00 2E 00 n.b.r.i.d.g.e...
# 0x0830: 6A 00 6E 00 62 00 63 00 6F 00 72 00 65 00 2E 00 j.n.b.c.o.r.e...
# 0x0840: 73 00 65 00 72 00 76 00 65 00 72 00 2E 00 62 00 s.e.r.v.e.r...b.
# 0x0850: 2E 00 63 00 2E 00 6F 00 28 00 55 00 6E 00 6B 00 ..c...o.(.U.n.k.
# 0x0860: 6E 00 6F 00 77 00 6E 00 20 00 53 00 6F 00 75 00 n.o.w.n. .S.o.u.
# 0x0870: 72 00 63 00 65 00 29 00 0D 00 0A 00 09 00 61 00 r.c.e.).......a.
# 0x0880: 74 00 20 00 63 00 6F 00 6D 00 2E 00 6A 00 6E 00 t. .c.o.m...j.n.
# 0x0890: 62 00 72 00 69 00 64 00 67 00 65 00 2E 00 6A 00 b.r.i.d.g.e...j.
# 0x08A0: 6E 00 62 00 63 00 6F 00 72 00 65 00 2E 00 73 00 n.b.c.o.r.e...s.
# 0x08B0: 65 00 72 00 76 00 65 00 72 00 2E 00 62 00 2E 00 e.r.v.e.r...b...
# 0x08C0: 63 00 2E 00 72 00 75 00 6E 00 28 00 55 00 6E 00 c...r.u.n.(.U.n.
# 0x08D0: 6B 00 6E 00 6F 00 77 00 6E 00 20 00 53 00 6F 00 k.n.o.w.n. .S.o.
# 0x08E0: 75 00 72 00 63 00 65 00 29 00 0D 00 0A 00 09 00 u.r.c.e.).......
# 0x08F0: 61 00 74 00 20 00 6A 00 61 00 76 00 61 00 2E 00 a.t. .j.a.v.a...
# 0x0900: 6C 00 61 00 6E 00 67 00 2E 00 54 00 68 00 72 00 l.a.n.g...T.h.r.
# 0x0910: 65 00 61 00 64 00 2E 00 72 00 75 00 6E 00 28 00 e.a.d...r.u.n.(.
# 0x0920: 54 00 68 00 72 00 65 00 61 00 64 00 2E 00 6A 00 T.h.r.e.a.d...j.
# 0x0930: 61 00 76 00 61 00 3A 00 36 00 31 00 39 00 29 00 a.v.a.:.6.1.9.).
# 0x0940: 0D 00 0A C0 00 ..... 

if (substr(r, 0, 3) == "JNB30" && 
   '\0I\0n\0v\0a\0l\0i\0d\0 \0r\0e\0q\0u\0e\0s\0t\0:\0' >< r)
{
 register_service(port:port, proto:"jnbproxy");
 security_note(port:port, data:'A ColdFusion jnbproxy is listening on this port.');

 exit(0);
}

# On port 510, submitted by Claus Bobjerg Juul
#
# 0x00:  0D 0A 0D 0A 54 68 69 73 20 69 73 20 61 20 46 69 ....This is a Fi
# 0x10:  72 73 74 43 6C 61 73 73 20 73 79 73 74 65 6D 2C rstClass system,
# 0x20:  20 66 72 6F 6D 20 4F 70 65 6E 20 54 65 78 74 20  from Open Text 
# 0x30:  43 6F 72 70 6F 72 61 74 69 6F 6E 2E 0D 0A 0D 0A Corporation.....
# 0x40:  0D 0A 46 69 72 73 74 43 6C 61 73 73 20 69 73 20 ..FirstClass is 
# 0x50:  61 6E 20 65 2D 6D 61 69 6C 20 61 6E 64 20 63 6F an e-mail and co
# 0x60:  6E 66 65 72 65 6E 63 69 6E 67 20 73 79 73 74 65 nferencing syste
# 0x70:  6D 20 77 69 74 68 20 61 20 67 72 61 70 68 69 63 m with a graphic
# 0x80:  61 6C 20 75 73 65 72 20 69 6E 74 65 72 66 61 63 al user interfac
# 0x90:  65 2E 0D 0A 0D 0A 0D 0A 54 68 65 20 43 6F 6D 6D e.......The Comm
# 0xA0:  61 6E 64 20 4C 69 6E 65 20 49 6E 74 65 72 66 61 and Line Interfa
# 0xB0:  63 65 20 69 73 20 6E 6F 74 20 61 76 61 69 6C 61 ce is not availa
# 0xC0:  62 6C 65 20 6F 6E 20 74 68 69 73 20 73 79       ble on this sy

if (match(string: r, pattern: '\r\n\r\nThis is a FirstClass system, from Open Text Corporation.\r\n\r\n*'))
{
 register_service(port:port, proto:"firstclass");
 security_note(port:port, data:'FirstClass is listening on this port.');

 exit(0);
}

# Submitted by Marc Verreault
# Software_installed=Impromptu V 7.3
# reference=http://www.cognos.com/products/series7/impromptu/
# listener=OSSERVER.EXE
# Port : 51025
# Type : get_http
# 0x00: 80 00 00 18 00 00 00 00 00 00 00 01 00 00 00 00 ................
# 0x10: 00 00 00 00 00 00 00 00 00 00 00 00             ............ 
if (r == '\x80\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' &&
   (report_paranoia > 1 || port == 51025) )
{
 register_service(port: port, proto:"impromptu");
 security_note(port: port, data: 'Cognos Impromptu is listening on this port.');

 exit(0);
}

# Submitted by Sean W. McDermott
# Port : 14502 / Type : get_http
# 0x00: 10 08 00 00 EC 03 00 00 08 00 00 00 02 00 00 00 ................
# 0x10: 00 00 00 00                                     ....
if (r == '\x10\x08\x00\x00\xEC\x03\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00')
{

 register_service(port:port, proto:"wcwservice");
 security_note(port:port, data: 'WhatChanged Agent from Prism Microsystems is listening on this port.');
# dead URL: http://www.prismmicrosys.com/WhatChanged.php
 exit(0);
}

#### Double check: all this should be handled by find_service.nes ####

# Spamd (port 783) - permissive Regex, just in case
if (r =~ '^SPAMD/[0-9.]+ [0-9]+ Bad header line:')
{
 register_service(port:port, proto:"spamd");
 security_note(port:port, data:"A SpamAssassin daemon is running on this port");
 exit(0);
}

if (r == 'GET / HTTP/1.0\r\n\r\n')
{
 report_service(port: port, svc: 'echo', banner: r);
 exit(0);
}

# Should we excluded port=5000...? (see find_service.c)
if (r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0); 
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if (r =~ '^[0-9][0-9][0-9]-?[ \t]')
{
 debug_print('"3 digits" found on port ', port, ' in response to GET\n');
 register_service(port: port, proto: 'three_digits');
 exit(0); 
}

if (r =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}

if (match(string: r, pattern: "Language received from client:*Setlocale:*"))
{
  report_service(port: port, svc: "websm");
  exit(0);
}

if (ereg(string: r, pattern: '^SSH-', icase: 0))
{
 report_service(port: port, svc: 'ssh');
 exit(0);
}

if (
  substr(r, 0, 3) == crap(data:raw_string(0), length:4) && 
  substr(r, 8, 18) == "00001$emsg="
)
{
 register_service(port:port, proto:"frontbase_db");
 security_note(port:port, data:"An instance of FrontBase is running on this port.");
 exit(0);
}

if (r == "<KU_goodbye>Protocol Error: XML data is not well-formed.</KU_goodbye>" 
)
{
 register_service(port:port, proto:"intermapperd");
 security_note(port:port, data:'An InterMapper service is listening on this port, and it allows\naccess from the Nessusd host.');
 exit(0);
}

# Listens by default on TCP port 2208 or 50000.
if (stridx(r, 'msg=MessageError\nresult-code=') == 0)
{
 register_service(port:port, proto:"hpiod");
 security_note(port:port, data:'An HP I/O backend daemon (hpiod) is listening on this port.');

 exit(0);
}

# Submitted by Francesco Conti
#
# More info: <http://sourceforge.net/projects/monopd/>
if (stridx(r, '<monopd><server version="') == 0)
{
 register_service(port:port, proto:"monopd");
 security_note(port:port, data:'monopd, a game server daemon for playing Monopoly-like board games, is\nlistening on this port.');

 exit(0);
}

# Submitted by Siraaj Khandkar.
if (stridx(r, '<boinc_gui_rpc_reply>') == 0)
{
 register_service(port:port, proto:"boinc_client");
 security_note(port:port, data:'A BOINC core client is listening on this port to allow GUI-based\nmanagement of the core client.');

 exit(0);
}

# Submitted by Christopher Rex.
#
# More info: <http://www.egghelp.org/>.
if (
  ("(Eggdrop v" >< r && " (C) 1997 Robey Pointer " >< r) ||
  # with stealth-telnets set to 1.
  '\r\nNickname.\r\n' == r ||
  ('\r\nNickname.\r\n' >< r && "You don't have access." >< r)
)
{
 register_service(port:port, proto:"eggdrop");
 security_note(port:port, data:'An Eggdrop IRC bot is listening on this port.');

 exit(0);
}

if (stridx(r, '\x07\x00\x00\x00APCX-OK') == 0)
{
 register_service(port:port, proto:'activepdf_server');
 security_note(port:port, data:"An activePDF Server is listening on this port.");
 exit(0);
}

# Submitted by Gary Cunninghame.
#
# More info: <http://www.firstclass.com/>.
if ("You have connected to a FirstClass System. Please login" >< r)
{
 register_service(port:port, proto:"firstclass");
 security_note(port:port, data:'A FirstClass Server is listening on this port.');

 exit(0);
}

# Submitted by Piotr Karanowski
if (r == 'UDAG')
{
 register_service(port:port, proto:"gg_dcc");
 security_note(port:port, data:'The remote service appears to be the file transfer service used by\nGadu-Gadu or a related instant message client.');

 exit(0);
}

# See <http://www.trimble.com/survey_wp_scalable.asp?Nav=Collection-27598>
# for an intro to Ntrip.
#
# Submitted by Jason Haar.
if (
  stridx(r, 'SOURCETABLE 200') == 0 &&
  '\nServer: ' >< r &&
  '\nContent-Type: ' >< r
)
{
 register_service(port:port, proto:"ntrip");
 security_note(port:port, data:'The remote service supports Ntrip, which provides streaming of\nreal-time GPS correction data.');

 exit(0);
}

# Submitted by Heath S. Hendrickson.
#
# Listens by default on TCP port 4750.
if (r =~ '^[0-9]+-[0-9];[0-9]+;[0-9]+;[0-9];[0-9a-h]+;[0-9a-h]+;[0-9]$')
{
 register_service(port:port, proto:"bladelogic_rscd");
 security_note(port:port, data:'A BladeLogic remote system call daemon (RSCD) is listening on this\nport.');

 exit(0);
}

# Submitted by Jason Spaltro.
if (
  '\nInvalid header checksum\n' >< r &&
  ' \x00h\x00e\x00a\x00d\x00e\x00r\x00' >< r
)
{
 register_service(port:port, proto:"encase_servlet");
 security_note(port:port, data:'The remote service appears to be an EnCase Servlet, a passive software\nagent used by EnCase for forensic analysis.');

 exit(0);
}

# R1Soft Windows Agent
#
# Submitted by Nils-Johan Johansson
if (
  stridx(r, '\xe1\xe7') == 0 &&
  (
    "Rejecting backup server (" >< r ||
    "__thiscall Net::ServerSocket::authenticate(void)" >< r
  )
)
{
  register_service(port:port, proto:"buagent");
  security_note(port:port, data:'A CDP Backup Agent from R1Soft is listening on this port.');
  exit(0);
}

# Check Point VPN-1/FireWall-1 NG services.
#
# Submitted by Mark Jenkins.
if ('Q\x00\x00\x00' == r)
{
 if (18183 == port)
 {
   register_service(port:port, proto:"fw1_sam");
   security_note(port:port, data:'The remote service appears to support the Check Point OPSEC Suspicious\nActivity Monitor API.');
   exit(0);
 }
 if (18187 == port)
 {
   register_service(port:port, proto:"fw1_ela");
   security_note(port:port, data:'The remote service appears to support the Check Point OPSEC Event\nLogging API.');
   exit(0);
 }
 if (18190 == port)
 {
   register_service(port:port, proto:"cpmi");
   security_note(port:port, data:'A Check Point Management Interface service is listening on this port.');
   exit(0);
 }
}


# Kaboodle Proxy, http://www.kaboodle.org/KaboodleProxy.html
#
# Submitted by Howard Gaskin.
if (stridx(r, 'KaboodleProxy_Protocol') == 0)
{
  register_service(port:port, proto:"kaboodle_proxy");
  security_note(
    port:port, 
    data:string(
      "A KaboodleProxy service is listening on this port.\n",
      "\n",
      "Kaboodle is an application for securely tunneling other applications\n",
      "and protocols, and a KaboodleProxy provides an easy way for Kaboodle\n",
      "users to locate and connect to each other.\n"
    )
  );
  exit(0);
}

# HASP License Manager Service
#
# Submitted by Derek Paterson
if (crap(data:'\xB8', length:0x3d)+'\xBA'+crap(data:'\x00', length:8) == r)
{
  register_service(port:port, proto:"tcpnethaspsrv");
  security_note(port:port, data:'A HASP License Manager Service is listening on this port.\n');
  exit(0);
}

# JNBridge
#
# Submitted by Tim Link.
if (
  r =~ '^JNB[0-9]+' && 
  # nb: unicode "com.jnbridge."
  'c\x00o\x00m\x00.\x00j\x00n\x00b\x00r\x00i\x00d\x00g\x00e\x00.' >< r
)
{
  register_service(port:port, proto:"jnbridge");
  security_note(
    port:port, 
    data:string(
      "The remote service is a JNBridgePro proxy, which enables Java and .NET\n",
      "code to interoperate."
    )
  );
  exit(0);
}


# Kiwi Syslog Daemon Service - Inter-App Communications Port.
#
# Submitted by Bill Wildprett.
if (r =~ "^KIWI[0-9]+")
{
  register_service(port:port, proto:"kiwi_syslogd_service");
  security_note(
    port:port, 
    data:string(
      "The remote service is a Kiwi Syslog Daemon Service - Inter-App\n",
      "communication port used by the Manager component to communicate with\n",
      "the associated Service."
    )
  );
  exit(0);
}

# HP Printer.
#
# nb: these banners can also be seen as spontaneous banners.
if (
  stridx(r, '@PJL USTATUS TIMED\r\n') == 0 ||
  stridx(r, '@PJL USTATUS DEVICE\r\n') == 0
)
{
  register_service(port:port, proto:"appsocket");
  security_note(port:port, data:'A Socket API service, commonly associated with print servers, is\nlistening on this port.');
  exit(0);
}

# NimBUS SLA Client Service, http://www.nimsoft.com/
#
# Submitted by Trygve Aasheim.
if (stridx(r, 'nimbus/1.0') == 0)
{
  register_service(port:port, proto:"nimbus_sla");
  security_note(port:port, data:'A NimBUS SLA client service is listening on this port.');
  exit(0);
}

# CommVault Client Event Manager Service, http://www.commvault.com/
#
# Submitted by Erik Harrison and Jon Bidinger and Don Weston.
if (
  stridx(r, '\x00\x00\x00\x09') == 0 &&
  stridx(r, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x32\x00\x00\x00\x01\x00\x00\x09\x5f') == 8 &&
  r_len == 8 + (ord(r[4]) << 24 | ord(r[5]) << 16 | ord(r[6]) << 8 | ord(r[7])) &&
  r_len == 0x20 + (ord(r[0x1c]) << 24 | ord(r[0x1d]) << 16 | ord(r[0x1e]) << 8 | ord(r[0x1f]))
)
{
  register_service(port:port, proto:"commvault_evmgrc");
  security_note(port:port, data:'A CommVault Client Event Manager Service (EvMgrC) is listening on this\nport.');
  exit(0);
}


# Logcaster Root Service, http://www.rippletech.com/information/products/nitroview-logcaster
#
# Submitted by Alex Beshirs.
if (stridx(r, 'N\x00i\x00t\x00r\x00o\x00V\x00i\x00e\x00w\x00 \x00L\x00o\x00g\x00C\x00a\x00s\x00t\x00e\x00r\x00') == 1)
{
  register_service(port:port, proto:"logcaster");
  security_note(
    port:port, 
    data:string(
      "A LogCaster Root Service is listening on this port.  It is a client-\n",
      "side agent that filters, processes and forwards Windows event logs\n",
      "to a LogCaster Server."
    )
  );
  exit(0);
}

# ESC/VP.net
#
# Submitted by Tim Doty.
if (substr_at_offset(str:r, blob:"ESC/VP.net\x10", offset:0))
{
  register_service(port:port, proto:"esc_vpnet");
  security_note(
    port:port, 
    data:
"The remote service understands ESC/VP.net, a control command and
protocol for Epson projectors."
  );
  exit(0);
}


#### Some spontaneous banners are coming slowly, so they are wronly 
#### registered as answers to GET
 
if (r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}


if((r_len > 8) && (substr(r,0,7) == '\x2E\x4E\x45\x54\x01\x00\x02\x00'))
{
 register_service(port:port, ipproto:"tcp", proto:"remoting_tcp");
 # nb: let dotnet_remoting_services_detect.nasl report it.
 exit(0);
}

# MWAgent runs on TCP port 2222 by default.
#
# nb: checking 'r' rather than 'r0' avoids mis-identifying the service.
if (
  r =~ '^Agent Ready' &&
  "GET / HTTP/1.0 501 command not implemented ERROR" >< r
)
{
 register_service(port:port, proto:"mwagent");
 security_note(port:port, data:'A MicroWorld Agent Service is listening on this port.  This service is\nused, for example, with the eScan Internet Security application from\nMicroWorld Technologies.');
 exit(0);
}


# LANDesk Inventory Service runs on TCP port 5007 by default.

if((r_len > 8) && (substr(r,0,7) == '\xFF\xFF\x01\x01\x00\x00\x04\x00'))
{
 register_service(port:port, ipproto:"tcp", proto:"landesk-inventory");
 security_note(port:port, data:'A LANDesk Inventory Service is listening on this port.');
 exit(0);
}

# SIP over TCP.
if( r =~ "^sip/[0-9]\.[0-9] ")
{
 register_service(port:port, ipproto:"tcp", proto:"sip");
 security_note(port:port, data:'A SIP service is listening on this port.');
 exit(0);
}

if ( ereg( string: r, pattern: '^:.* 451 \\* :You have not registered\\.\r\n',
   	   multiline: 1))
{
  register_service(port: port, proto: "irc-bnc");
  security_note(port: port, data: "Night Light IRC Proxy is listening on this port");
  exit(0);
}
