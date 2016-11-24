#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34970);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2009-3548");
 script_bugtraq_id(36954);
 script_xref(name:"OSVDB", value:"60176");

 script_name(english: "Apache Tomcat Manager Common Administrative Credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"The management console for the remote web server is protected using a
known set of credentials." );
 script_set_attribute(attribute:"description", value:
"It is possible to gain access to the Manager web application for the
remote Tomcat server using a known set of credentials.  A remote
attacker can leverage this issue to install a malicious application on
the affected server and run code with Tomcat's privileges (usually
SYSTEM on Windows, or the unprivileged 'tomcat' account on Unix). 

Worms are known to propagate this way." );
 script_set_attribute(attribute:"see_also", value:"http://markmail.org/thread/wfu4nff5chvkb6xp" );
 script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=834047" );
 script_set_attribute(attribute:"solution", value:
"Change the administrator's password in tomcat-users.xml." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_summary(english: "Try common passwords for Tomcat"); 
 script_category(ACT_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/tomcat");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

n = 0;
user[n] = "tomcat";	pass[n++] = "tomcat";
user[n] = "admin";	pass[n++] = "admin";
user[n] = "admin";	pass[n++] = "";

port = get_http_port(default:8080);

if (!thorough_tests)
{
 banner = get_http_banner(port: port);
 if ("Apache-Coyote" >!< banner) exit(0);
}

function test(port, user, pass, page)
{
 local_var	r;

 r = http_send_recv3(port: port, username: user, password: pass, method: "GET", item: page);
 if (isnull(r)) exit(0);
 if (r[0] !~ "^HTTP/1\.[01] 200 ") return 0;
 if ("The Apache Software Foundation" >!< r[2]) return 0;
 if ("deployConfig" >!< r[2] || "deployWar" >!< r[2]) return 0;
 return 1;
}

u = "/manager/html";
r = http_send_recv3(port: port, method: "GET", item:u, username:"", password:"");
if (isnull(r)) exit(0);
if (r[0] !~ "^HTTP/1\.[01] 401 ") exit(0);
if ("Tomcat Manager Application" >!< r[1]) exit(0);

for (i = 0; i < n; i ++)
  if (test(port: port, user: user[i], pass: pass[i], page: u))
  {
    report = strcat('\nIt is possible to log into the Tomcat Manager web app at the\nfollowing URL :\n\n  ', 
      build_url(port: port, qs: u), 
      '\n\nwith the following credentials :\n\n  - Username : ', user[i], '\n  - Password : ', pass[i], '\n');
    security_hole(port: port, extra: report);
    exit(0);
  }
