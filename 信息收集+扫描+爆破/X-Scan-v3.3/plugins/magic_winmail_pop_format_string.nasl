#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11742);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2003-0391");
 script_bugtraq_id(7667);
 script_xref(name:"OSVDB", value:"4921");
 
 script_name(english:"Magic Winmail Server PASS Command Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a format string attack." );
 script_set_attribute(attribute:"description", value:
"The remote Winmail POP server, according to its banner, is vulnerable
to a format string attack when processing the USER command. 

An unauthenticated attacker may use this flaw to execute arbitrary
code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0251.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.magicwinmail.net/changelog.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinMail version 2.4 (Build 0530) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Magic WinMail banner check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

banner = get_kb_item(string("pop3/banner/", port));
if(!banner)
{
    if(get_port_state(port))
    {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
    }
}

if(banner)
{
    if(ereg(pattern:".*Magic Winmail Server (1\..*|2\.[0-3][^0-9])", string:banner, icase:TRUE))
    {
	security_hole(port);
    }
}
