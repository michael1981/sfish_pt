#
# This script is (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(17209);
 script_cve_id("CVE-2005-0526", "CVE-2005-0630", "CVE-2005-0631");
 script_bugtraq_id(12631, 12633, 12666, 12690, 12694);
 script_xref(name:"OSVDB", value:"14360");

 script_version ("$Revision: 1.14 $");
 name["english"] = "PBLang BBS <= 4.65 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
PBLang BBS, a bulletin board system written in PHP, that suffers from
the following vulnerabilities:

  - HTML Injection Vulnerability in pmpshow.php.
    An attacker can inject arbitrary HTML and script into the
    body of PMs sent to users allowing for theft of 
    authentication cookies or misrepresentation of the site.

  - Cross-Site Scripting Vulnerability in search.php.
    If an attacker can trick a user into following a specially
    crafted link to search.php from an affected version of
    PBLang, he can inject arbitrary script into the user's 
    browser to, say, steal authentication cookies.

  - Remote PHP Script Injection Vulnerability in ucp.php.
    PBLang allows a user to enter a PHP script into his/her 
    profile values, to be executed with the permissions of
    the web server user whenever the user logs in. 

  - Directory Traversal Vulnerability in sendpm.php.
    A logged-in user can read arbitrary files, subject to
    permissions of the web server user, by passing full
    pathnames through the 'orig' parameter when calling
    sendpm.php.

  - Arbitrary Personal Message Deletion Vulnerability in delpm.php.
    A logged-in user can delete anyone's personal messages by
    passing a PM id through the 'id' parameter and a username 
    through the 'a' parameter when calling delpm.php." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0406.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0407.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0015.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0019.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6808b6a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PBLang 4.66z or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in PBLang BBS <= 4.65";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencies("http_version.nasl");
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

function check(loc)
{
  local_var res;

  res = http_get_cache(port:port, item: loc + "/index.php");
  if (isnull(res)) exit(0);
  if ( 
    "PBLang Project" >< res && 
    egrep(pattern:'<meta name="description" content=".+running with PBLang ([0-3]\\.|4\\.[0-5]|4\\.6[0-5])">', string:res)
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0); 
  }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
