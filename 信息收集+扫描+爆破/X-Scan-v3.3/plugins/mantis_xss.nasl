#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
#  Ref: Paul Richards
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, OSVDB refs (3/25/2009)


include("compat.inc");

if(description)
{
 script_id(14344);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(9184);
 script_xref(name:"OSVDB", value:"2934");

 script_name(english:"Mantis < 0.18.1 Multiple Unspecified XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone
to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of Mantis contains a flaw
in the handling of some types of input.  Because of this, an attacker
may be able to cause arbitrary HTML and script code to be executed in
a user's browser within the security context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=202559" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.18.1 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.0[^0-9])", string:ver))
  {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
