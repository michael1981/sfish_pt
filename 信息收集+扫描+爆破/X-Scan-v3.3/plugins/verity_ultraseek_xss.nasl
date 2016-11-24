#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Michael Krax
# This script is released under the GNU GPL v2
#

include("compat.inc");

if(description)
{
  script_id(17226);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2005-0514");
  script_bugtraq_id(12617);
  script_xref(name:"OSVDB", value:"14045");
   
  script_name(english:"Verity Ultraseek Search Request XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultraseek, an enterprise search engine. 
This version has a cross-site scripting vulnerability.  Successful
exploitation of this issue may allow an attacker to execute malicious
script code on a vulnerable server."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Ultraseek 5.3.3 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_summary(english:"Checks  Verity Ultraseek search request XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 8765);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8765);
if (!port) exit(0);
 
if ( ! get_port_state(port))exit(0);

function check(loc)
{
  local_var buf, r;
  buf = http_get(item:string(loc,"/help/copyright.html"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  if( r == NULL )exit(0);
  
  #<h3>Verity Ultraseek 5.3.1</h3>
  if(("<title>About Verity Ultraseek</title>" >< r) && 
   egrep(pattern:"Verify Ultraseek 5\.([23]\.[12]|3[^0-9])", string:r))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
