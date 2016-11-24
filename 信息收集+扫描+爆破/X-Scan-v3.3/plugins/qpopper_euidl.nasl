#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10423);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0320");
 script_bugtraq_id(1133);
 script_xref(name:"OSVDB", value:"325");
 
 script_name(english:"Qpopper EUIDL Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host
through the remote POP server" );
 script_set_attribute(attribute:"description", value:
"The remote version of the Qpopper POP server contains a bug
which may allow authenticated users who have a pop account 
to gain a shell with the gid 'mail' by sending to themselves a 
specially crafted mail." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest Qpopper software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"checks for the version of Qpopper");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;


banner = get_pop3_banner(port:port);
if ( ! banner ) exit(0);

if(ereg(pattern:"^\+OK QPOP \(version (2\.((5[3-9]+)|([6-9][0-9]+))\)|3\.0).*$", string:banner)) security_warning(port);
	  

