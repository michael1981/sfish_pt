#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12096);
 script_cve_id("CVE-2004-1806");
 script_bugtraq_id(9854, 9856);
 script_xref(name:"OSVDB", value:"4229");
 script_xref(name:"OSVDB", value:"4230");
 script_xref(name:"Secunia", value:"11112");
 
 script_version("$Revision: 1.13 $");
 script_name(english:"cfWebStore Multiple Vulnerabilities (SQLi, XSS)");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has multiple\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running cfWebStore 5.0.0 or older.\n\n",
     "There is a flaw in this software which may allow a remote attacker to\n",
     "execute arbitrary SQL statements in the remote database, which may in\n",
     "turn be used to gain administrative access on the remote host, read,\n",
     "or modify the content of the remote database.\n\n",
     "Additionally, cfWebStore is reportedly vulnerable to a cross-site\n",
     "scripting issue. However, Nessus has not tested for this."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-03/0122.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cfWebStore version 5.0.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(dir)
{
  local_var buf, url;
  url = string(dir, "/index.cfm?fuseaction=category.display&category_ID='"); 
  buf = http_send_recv3(method:"GET", item:url, port:port);
  if(isnull(buf))exit(0);
  if ("cfquery name=&quot;request.QRY_GET_CAT&quot;" >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 return(0);
}

foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
