#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16180);
 script_version("$Revision: 1.5 $");

 script_bugtraq_id(12284); 
 script_xref(name:"OSVDB", value:"13094");
 script_xref(name:"Secunia", value:"13896");

 script_name(english:"SiteMinder smpwservicescgi.exe Arbitrary Site Redirect");
 script_summary(english:"Checks for a flaw in SiteMinder");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is affected by a redirection weakness."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running Netegrity SiteMinder, an access management\n",
   "solution. \n",
   "\n",
   "The remote version of this software is vulnerable to a page injection\n",
   "flaw that may allow an attacker to trick users into sending him their\n",
   "credentials via a link to the 'smpwservicescgi.exe' program with a\n",
   "rogue TARGET argument value which will redirect them to an arbitrary\n",
   "website after they authenticate to the remote service."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://www.scip.ch/cgi-bin/smss/showadv.pl?id=1022"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0569.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
req = http_get(port:port, item:dir + "/pwcgi/smpwservicescgi.exe?TARGET=http://www.nessus.org");
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( '<input type=hidden name=TARGET value="http://www.nessus.org">' >< res &&
     '<form NAME="PWChange" METHOD="POST" ACTION="/siteminderagent/pwcgi/smpwservicescgi.exe">' >< res )
 {
	 security_warning(port);
	 exit(0);
 }
}
