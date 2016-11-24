#
# (C) Tenable Network Security, Inc.
#

# Ref:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: sendmail -bt negative index bug...
# From: Michal Zalewski <lcamtuf@DIONE.IDS.PL>
# Date: Sun, 8 Oct 2000 15:12:46 +0200 
#


include("compat.inc");

if(description)
{
 script_id(10809);
 script_version ("$Revision: 1.18 $");
 script_xref(name:"OSVDB", value:"676");
 
 script_name(english:"Sendmail < 8.11.2 -bt Option Local Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is reportedly affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote sendmail server, according to its version number, may be
vulnerable to a '-bt' overflow attack that allows a local user to
execute arbitrary commands as root." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-10/0109.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-01/0003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail version 8.11.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 script_summary(english:"Checks the version number"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("global_settings.inc");

if ( report_paranoia > 1 ) exit(0);


port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:"Sendmail.*([^/](8\.(([0-9]\..*)|(10\..*)|(11\.[01])))|SMI-8\.).*",
	string:banner))
 	security_hole(port);
}
