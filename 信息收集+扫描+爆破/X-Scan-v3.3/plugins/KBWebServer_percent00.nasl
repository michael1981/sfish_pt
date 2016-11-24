#
# (C) Tenable Network Security, Inc.
#

# This script was written starting from roxen_percent.nasl
#
# References:
# From:"Securiteinfo.com" <webmaster@securiteinfo.com>
# To:nobody@securiteinfo.com
# Date: Sun, 7 Jul 2002 21:42:47 +0200 
# Message-Id: <02070721424701.01082@scrap>
# Subject: [VulnWatch] KF Web Server version 1.0.2 shows file and directory content
#

include("compat.inc");

if(description)
{
 script_id(11166);
 script_version ("$Revision: 1.11 $");

 script_xref(name:"OSVDB", value:"5026");

 script_name(english:"KeyFocus (KF) Web Server Null Byte Request Restricted File / Directory Access");
 script_summary(english:"Make a request like http://www.example.com/%00");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server is affected by an information disclosure\n",
   "vulnerability."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The installed version of KF Web Server returns a directory listing\n",
   "when the request URL contains a URL-encoded NULL byte (%00) after the\n",
   "directory name."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0007.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.keyfocus.net/kfws/support/"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Upgrade to KF Web Server version 1.0.3."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2002/07/07"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2002/11/25"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure it's KF Web Server.
banner = get_http_banner(port:port);
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
if ("Server: KFWebServer/" >!< banner) 
  exit(0, "The banner for port "+port+" is not from KF Web Server.");

r = http_send_recv3(method:"GET",item:"/%00", port:port);
if (isnull(r)) exit(1, "The web server on port "+port+" did not respond.");

data = strcat(r[0], r[1], '\r\n', r[2]);

if (egrep(string: data, pattern: ".*File Name.*Size.*Date.*Type.*"))
{
 security_warning(port);
}
