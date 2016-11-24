#
# (C) Tenable Network Security
#
#


include("compat.inc");

if (description)
{
 script_id(15643);
 script_bugtraq_id(11611);
 script_version ("$Revision: 1.3 $");

 script_name(english:"IceWarp Web Mail Multiple Flaws (2)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web servier is hosting an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues which may allow an attacker to compromise the
integrity of the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc61aa25" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/380446/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.3.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("icewarp_webmail_vulns.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:32000);

version = get_kb_item("www/" + port + "/icewarp_webmail/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.([0-2]\.|3\.0))", string:version) )
	security_warning(port);
