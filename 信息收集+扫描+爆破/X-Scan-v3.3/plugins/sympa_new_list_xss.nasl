#
# (C) Tenable Network Security, Inc.
#

# based on work from David Maciejak



include("compat.inc");

if(description)
{
 script_id(14323);
 script_version ("$Revision: 1.14 $"); 

 script_cve_id("CVE-2004-1735");
 script_bugtraq_id(10992);
 script_xref(name:"OSVDB", value:"9081");
 script_xref(name:"Secunia", value:"12339");

 script_name(english:"Sympa New List Creation Description Field XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Sympa on the
remote host contains an HTML injection vulnerability that may allow a
user who has the privileges to create a new list to inject HTML tags
in the list description field." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0293.html" );
 script_set_attribute(attribute:"solution", value:
"Update to version 4.1.3 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks sympa version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencies("sympa_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/sympa"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if (ver =~ "^(2\.|3\.|4\.0\.|4\.1\.[012]([^0-9]|$))")
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
