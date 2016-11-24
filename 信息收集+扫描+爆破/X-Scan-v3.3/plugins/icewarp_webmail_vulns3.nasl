#
# (C) Tenable Network Security
#
#


include("compat.inc");

if (description)
{
 script_id(16273);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2005-0320", "CVE-2005-0321");
 script_bugtraq_id(12396);
 script_xref(name:"OSVDB", value:"13368");
 script_xref(name:"OSVDB", value:"13369");
 script_xref(name:"OSVDB", value:"13370");
 script_xref(name:"OSVDB", value:"13371");
 script_xref(name:"OSVDB", value:"13372");
 script_xref(name:"OSVDB", value:"13373");
 script_xref(name:"OSVDB", value:"13374");
 script_xref(name:"OSVDB", value:"13375");
 script_xref(name:"OSVDB", value:"13376");
 script_xref(name:"OSVDB", value:"13377");

 script_name(english:"IceWarp Web Mail Multiple Flaws (3)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a webmail application that is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues which may allow an attacker to compromise the
integrity of the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/388751/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.3.3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:version) )
	security_warning(port);
