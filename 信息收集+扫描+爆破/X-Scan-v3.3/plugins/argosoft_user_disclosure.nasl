#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16094);
 script_cve_id("CVE-2004-1428");
 script_bugtraq_id(12139);
 script_xref(name:"OSVDB", value:"11335");
 script_version("$Revision: 1.14 $");
 
 script_name(english:"ArGoSoft FTP Server USER Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP Server. 

The remote version of this software returns different error messages
when a user attempts to log in using a nonexistent username or a bad
password. 

An attacker may exploit this flaw to launch a dictionary attack
against the remote host in order to obtain a list of valid user names." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501c2e30" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft FTP 1.4.2.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks the error message of the remote FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = ftp_recv_line(socket:soc);
if ("ArGoSoft" >!< banner ) exit(0);
send(socket:soc, data:'USER nessus' + rand() + rand() + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
if ( egrep(string:r, pattern:"^530 User .* does not exist", icase:TRUE) )
	security_warning(port);
ftp_close(socket:soc);
