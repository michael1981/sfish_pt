#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17142);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-0474");
 script_bugtraq_id(12581);
 script_xref(name:"OSVDB", value:"13918");

 script_name(english:"WebCalendar login.php webcalendar_session Cookie SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of WebCalendar contains a SQL injection
vulnerability that may allow an attacker to execute arbitrary SQL
statements against the remote database.  An attacker may be able to
leverage this issue to, for example, delete arbitrary database tables." );
 script_set_attribute(attribute:"see_also", value:"http://www.scovettalabs.com/advisory/SCL-2005.001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110868446431706&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 0.9.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Sends a malformed cookie to the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 set_http_cookie(name: "webcalendar_session", value: "7d825292854146");
 r = http_send_recv3(method: "GET", item:dir + "/views.php", port:port);
 if (isnull(r)) return(0);
 if ( "<!--begin_error(dbierror)-->" >< r[2] )
 {
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
