#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15987);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2004-1407", "CVE-2004-1408", "CVE-2004-1409");
 script_bugtraq_id(11990);
 script_xref(name:"OSVDB", value:"12569");
 script_xref(name:"OSVDB", value:"12570");
 script_xref(name:"OSVDB", value:"12571");
 script_xref(name:"OSVDB", value:"12572");
 script_xref(name:"OSVDB", value:"12573");
 
 script_name(english:"Singapore Gallery < 0.9.11 Multiple Vulnerabilities");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a PHP script that is affected by\n",
   "multiple vulnerabilities."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "Singapore is a PHP based photo gallery web application.\n",
   "\n",
   "The remote version of this software is affected by multiple\n",
   "vulnerabilities that may allow an attacker to read arbitray\n",
   "files on the remote host or to execute arbitrary PHP commands."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0211.html"
  );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.nessus.org/u?78dc82b5"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to Singapore 0.9.11 or later."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_summary(english:"The presence of Singapore Gallery");
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

foreach dir (cgi_dirs())
{
 buf = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (isnull(buf)) exit(0);

 if(egrep(pattern:"Powered by.*singapore\..*singapore v0\.([0-8]\.|9\.([0-9][^0-9]|10))", string:buf) )
	{
 	security_warning(port);
	exit(0);
	}
}
