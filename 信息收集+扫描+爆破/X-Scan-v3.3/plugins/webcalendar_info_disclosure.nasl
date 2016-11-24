#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/13/2009)


include("compat.inc");

if(description)
{
 script_id(21566);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2006-2247");
 script_bugtraq_id(17853);
 script_xref(name:"OSVDB", value:"25280");

 script_name(english:"WebCalendar Login Error Message User Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of WebCalendar on the remote host is prone to a user
account enumeration weakness in that in response to login attempts it
returns different error messages depending on whether the user exists
or the password is invalid." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/433053/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/436263/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fe61fc9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 1.0.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"Checks for WebCalendar User Account Enumeration Disclosure weakness");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/login.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  if ("webcalendar_session=deleted; expires" >< res && '<input name="login" id="user"' >< res)
  {
    postdata=string(
	  "login=nessus", unixtime(), "&",
	  "password=nessus"
    );
    req = string(
   "POST ", url, " HTTP/1.1\r\n",
	 "Host: ", get_host_name(), "\r\n",
	 "Content-Type: application/x-www-form-urlencoded\r\n",
	 "Content-Length: ", strlen(postdata), "\r\n",
	 "\r\n",
	 postdata
    );

    #display("req='", req, "'.\n");
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    #display("res='", res, "'.\n");
    if (res == NULL) exit(0);

    if ("Invalid login: no such user" >< res) {
	security_warning(port);
    }
  }
}
