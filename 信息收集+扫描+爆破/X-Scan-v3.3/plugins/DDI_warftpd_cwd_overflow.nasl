#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (1/22/2009)
# - Revised plugin title (2/04/2009)

include("compat.inc");

if(description)
{
	script_id(11205);
	script_version("$Revision: 1.7 $");

	script_cve_id("CVE-2000-0131");
	script_bugtraq_id(966);
	script_xref(name:"OSVDB", value:"4677");
	
	script_name(english:"WarFTPd CWD/MKD Command Overflow");
	script_summary(english:"War FTP Daemon CWD/MKD Buffer Overflow");

	script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is prone to a buffer overflow attack.");
	script_set_attribute(attribute:"description", value:
"The version of the War FTP Daemon running on this host is vulnerable
to a buffer overflow attack.  This is due to improper bounds checking
within the code that handles both the CWD and MKD commands.  By
exploiting this vulnerability, it is possible to crash the server.");
	script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2000-01/0480.html");
	script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2000-01/0507.html");
	script_set_attribute(attribute:"solution", value:
"Upgrade to WarFTPd version 1.67-4 or later.");
	script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
	script_end_attributes();

	script_category(ACT_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2003-2009 Digital Defense, Inc.");
	script_family(english:"FTP");
	script_require_ports("Services/ftp", 21);
	script_dependencies("find_service_3digits.nasl");
	exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
	r = get_ftp_banner(port:port);
	if(!r)exit(0);
	
	if(("WAR-FTPD 1.66x4" >< r) || ("WAR-FTPD 1.67-03" >< r))
	{
		security_warning(port);
	}
}
