#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10588);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0206");
 script_xref(name:"OSVDB", value:"485");
 
 script_name(english:"Sendmail mime7to8() Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number,
may be vulnerable to a MIME buffer overflow attack which
allows anyone to execute arbitrary commands as root." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Sendmail." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	
script_end_attributes();

 script_summary(english: "Checks sendmail version number");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc."); 
 script_family(english: "SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:"Sendmail.*[^/]8\.8\.[01]/.*", string:banner))
 	security_hole(port);
}
