#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15561);
 script_cve_id("CVE-2004-1622");
 script_bugtraq_id(11502);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"11050");
 }

 script_version("$Revision: 1.10 $");
 name["english"] = "UBB.threads dosearch.php SQL injection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"There is a SQL injection issue in the remote version of UBB.threads
that may allow an attacker to execute arbitrary SQL statements on the
remote host and potentially overwrite arbitrary files there by sending
a malformed value to the 'Name' argument of the file 'dosearch.php'." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109839925207038&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "SQL Injection in UBB.threads";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencies("ubbthreads_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 r = http_send_recv3(method:"GET", port:port, item: dir + "/dosearch.php?Name=42'");
 if (isnull(r)) exit(0);
 res = r[2];
 if ( "mysql_fetch_array()" >< res )
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
