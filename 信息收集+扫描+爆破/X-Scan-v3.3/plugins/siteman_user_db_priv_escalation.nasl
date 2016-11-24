#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16216);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0305");
  script_bugtraq_id(12304, 12558);
  script_xref(name:"OSVDB", value:"13131");

  script_name(english:"Siteman Page User Database Privilege Escalation");
  script_summary(english:"Checks Siteman's version");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is prone to\n",
      "a privilege escalation attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Siteman, a web-based content management\n",
      "system written in PHP.\n",
      "\n",
      "The remote version of this software is affected by a privilege\n",
      "escalation vulnerability.  An attacker with a valid username and\n",
      "password may escalate his privileges by making a specially crafted\n",
      "request to the remote server."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0239.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Siteman 1.1.11 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2008 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
buf = http_get(item:dir + "/forum.php", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if(isnull(r))exit(0);

if( '<meta name="generator" content="Siteman ' >< r )
{
  line = egrep(pattern:'<meta name="generator" content="Siteman (0\\.|1\\.(0|1\\.([0-9][^0-9]|10[^0-9])))', string:r);
  if ( line ) 
  {
  security_warning(port);
  exit(0);
  }
 }
}
