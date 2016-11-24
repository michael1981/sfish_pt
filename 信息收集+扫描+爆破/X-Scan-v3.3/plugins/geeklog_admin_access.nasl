#
# (C) Tenable Network Security, Inc.
#
# Date: Thu, 29 May 2003 13:02:55 +0800
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Geeklog 1.3.7sr1 and below multiple vulnerabilities.

include("compat.inc");

if(description)
{
 script_id(11670);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2002-0096", "CVE-2002-0097", "CVE-2002-0962", 
"CVE-2003-1347");
 script_bugtraq_id(3783, 3844, 4969, 4974, 6601, 6602, 6603, 6604, 7742, 7744);
 script_xref(name:"OSVDB", value:"2016");
 script_xref(name:"OSVDB", value:"2021");
 script_xref(name:"OSVDB", value:"4811");
 script_xref(name:"OSVDB", value:"4812");
 script_xref(name:"OSVDB", value:"4813");
 script_xref(name:"OSVDB", value:"8073");
 script_xref(name:"OSVDB", value:"8074");
 script_xref(name:"OSVDB", value:"8075");

 script_name(english:"Geeklog <= 1.3.7sr1 Multiple Vulnerabilities (SQLi, XSS, Priv Esc)");
 script_summary(english:"sends a rotten cookie to the remote host");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a PHP application that is affected by\n",
   "multiple vulnerabilities."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote server is running a version of Geeklog affected by various\n",
   "vulnerabilities, including SQL injection, arbitrary file upload,\n",
   "privilege escalation, etc."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0322.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Unknown at this time."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 
 script_family(english:family["english"]);
 script_dependencies("geeklog_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
			 

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 dir = matches[2];

 init_cookiejar();

 set_http_cookie(name: "geelog", value: "2.1");
 r = http_send_recv3(method: "GET", item:dir + "/users.php", port:port);
 if (isnull(r)) exit(0);

 if (get_http_cookie(name: "gl_session"))
 { 
   security_hole(port);
   exit(0);
 }
} 
