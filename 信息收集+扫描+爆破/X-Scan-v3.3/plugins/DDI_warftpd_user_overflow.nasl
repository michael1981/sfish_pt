#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)


include("compat.inc");

if(description)
{
	script_id(11207);
	script_version("$Revision: 1.10 $");

	script_cve_id("CVE-1999-0256");
	script_bugtraq_id(10078);
	script_xref(name:"OSVDB", value:"875");
	
	script_name(english:"WarFTPd USER/PASS Command Remote Overflow");
	script_summary(english:"War FTP Daemon USER/PASS Overflow");

	script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote FTP server." );
	script_set_attribute(attribute:"description", value:
"The version of War FTP Daemon running on this host contains a buffer
overflow in the code that handles the USER and PASS commands.  A
potential intruder could use this vulnerability to crash the server,
as well as run arbitrary commands on the system." );
	script_set_attribute(attribute:"solution", value:
"Upgrade to WarFTPd version 1.66x4 or later.");
	script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2009 Digital Defense, Inc.");
	script_family(english:"FTP");
	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);

	if(egrep(pattern:"WAR-FTPD 1.([0-5][0-9]|6[0-5])[^0-9]*Ready",string:r, icase:TRUE))
	{
		security_hole(port);
	}
}
