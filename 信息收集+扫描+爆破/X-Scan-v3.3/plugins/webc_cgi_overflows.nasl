#
# (C) Tenable Network Security, Inc.
#
#
# Ref:
# From: Carl Livitt <carl@learningshophull.co.uk>
# To: bugtraq@securityfocus.com
# Subject: Multiple vulnerabilities in AutomatedShops WebC shopping cart
# Date: Thu, 3 Apr 2003 14:22:36 +0100

include( 'compat.inc' );

if(description)
{
  script_id(11516);
  script_bugtraq_id(7268, 7277);
  script_xref(name:"OSVDB", value:"49359");
  script_xref(name:"OSVDB", value:"49360");

  script_version ("$Revision: 1.6 $");

  script_name(english:"AutomatedShops WebC.cgi Multiple Overflows");
  script_summary(english:"Checks for the presence of webc.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running a version of AutomatedShops's webc.cgi
which is older than version 5.020.

This CGI is vulnerable to a remote buffer overflow (up to version 5.005 included)
and to a local one (up to version 5.010 included)

An attacker may use this flaw to execute arbitrary code on the remote
host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to version 5.020"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/317344'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc." );
  script_family(english:"CGI abuses");
  script_dependencie("webc_cgi_installed.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

version = get_kb_item(string("www/", port, "/content/webc.cgi/version"));
if(version)
{
 if(ereg(pattern:"([0-4]\..*|5\.0([0-1][0-9])) ", string:version))
 	security_hole(port);
}
