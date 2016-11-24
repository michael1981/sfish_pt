#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14613);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2004-1651");
 script_bugtraq_id(11080);
 script_xref(name:"OSVDB", value:"9450");
 script_xref(name:"OSVDB", value:"9451");
 
 script_name(english:"phpScheduleIt 1.0.0 RC1 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpScheduleIt on the remote
host is earlier than 1.0.0.  Such versions are vulnerable to HTML
injection issues.  For example, an attacker may add malicious HTML and
JavaScript code in a schedule page if he has the right to edit the
'Schedule Name' field.  This field is not properly sanitized.  The
malicious code would be executed by a victim web browser displaying
this schedule." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0417.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0216.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpScheduleIt version 1.0.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks version of phpScheduleIt");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpscheduleit_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Check an install.
install = get_kb_item(string("www/", port, "/phpscheduleit"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];

  if (ereg(pattern:"^(0\..*|1\.0\.0 RC1)", string:ver))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
