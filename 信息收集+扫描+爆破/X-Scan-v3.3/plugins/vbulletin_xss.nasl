#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Cheng Peng Su
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title (4/26/009)


include("compat.inc");

if(description)
{
 script_id(14792);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0620");
 script_bugtraq_id(10602, 10612);
 script_xref(name:"OSVDB", value:"7256");
  
 script_name(english:"vBulletin newreply.php WYSIWYG_HTML Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote version of vBulletin is vulnerable
to a cross-site scripting issue, due to a failure of the application
to properly sanitize user-supplied input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-06/0386.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 3.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks the version of vBulletin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("vbulletin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '^3.0(\\.[01])?[^0-9]' )
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
