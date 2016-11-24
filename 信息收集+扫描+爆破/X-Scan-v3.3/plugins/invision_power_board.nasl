#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11273);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-1385");
 script_bugtraq_id(6976, 7204);
 script_xref(name:"OSVDB", value:"3357");
 script_xref(name:"OSVDB", value:"3371");
 
 script_name(english:"Invision Power Board ipchat.php root_path Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file inclusion attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using Invision Power Board. The ipchat.php script 
fails to sanitize input passed to the 'root_path' parameter.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server. 

In addition, the ad_member.php script has been reported vulnerable. 
However, Nessus has not checked for that script." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0099.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for root_path include flaw in ipchat.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("invision_power_board_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    dir = matches[2];

    req = http_get(item:string(dir, "/ipchat.php?root_path=http://xxxxxxxx/"),
	port:port);
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( r == NULL )exit(0);
    if(egrep(pattern:".*http://xxxxxxxx/conf_global.php.*", string:r))
    {
      security_hole(port);
      exit(0);
    }
  }
}
