#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(40825);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2009-3023");
 script_bugtraq_id(36189);
 script_xref(name:"OSVDB", value:"57589");

 script_name(english:"MS09-053: Microsoft IIS FTPd NLST Command Remote Buffer Overflow (975191) (uncredentialed check)");

 script_set_attribute(attribute:"synopsis", value:
"The remote anonymous FTP server seems vulnerable to an arbitrary code
execution attack." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server allows anonymous users to create directories in
one or more locations. 

The remote version of this server is vulnerable to a buffer overflow
attack in the NLST command which, when coupled with the ability to
create arbitrary directories, may allow an attacker to execute
arbitrary commands on the remote Windows host with SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 5.0, 5.1, 6.0, and
7.0 :

http://www.microsoft.com/technet/security/Bulletin/MS09-053.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://securityvulns.com/files/iiz5.pl" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/276653" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/advisory/975191.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_dependencie("ftp_anonymous.nasl", "ftp_writeable_directories.nasl");
 script_summary(english:"Checks the version of IIS FTP");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/tested_writeable_dir");
 exit();
}

#
# The script code starts here
#

include("global_settings.inc");
include('ftp_func.inc');

exit(0);


dir = get_kb_item("ftp/tested_writeable_dir");
if ( isnull(dir) ) exit(0, "No writeable dir found");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(1, "Port " + port + " is marked as closed");
banner = get_ftp_banner(port:port);
if ( isnull(banner) ) exit(1, "Could not retrieve the FTP server's banner");
if ( egrep(pattern:"^22.* Microsoft FTP Service \(Version 5\.[01]\)", string:banner) )
	security_hole(port, extra:'The directory ' + dir + ' could be used to exploit the server');
else if ( !egrep(pattern:"^22.* Microsoft FTP Service \(Version ", string:banner )) {
    soc = open_sock_tcp(port);
    if ( ! soc ) exit(1, "Could not connect to the remote FTP server");
    banner = ftp_recv_line(socket:soc);
    if ( ! ftp_authenticate(user:"anonymous", pass:"joe@", socket:soc) ) exit(1, "Could not log into the remote FTP server");
    send(socket:soc, data:'STAT\r\n');
    r = ftp_recv_line(socket:soc);
    if ( "Microsoft Windows NT FTP Server status" >< r &&
	 ("Version 5.0" >< r || "Version 5.1" >< r ) ) security_hole(port, extra:'The directory ' + dir + ' could be used to exploit the server');
 }
