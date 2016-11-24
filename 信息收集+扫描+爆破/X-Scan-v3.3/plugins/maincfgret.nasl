#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15564);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0798");
 script_bugtraq_id(11043);
 script_xref(name:"OSVDB", value:"9177");
 
 script_name(english:"Ipswitch WhatsUp Gold _maincfgret.cgi Remote Overflow");
 script_summary(english:"Checks for the presence of /_maincfgret.cgi");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The '_maincfgret' CGI is installed on the remote web server.  Some\n",
     "versions are vulnerable to a buffer overflow.  Note that Nessus\n",
     "only checked for the presence of this CGI, and did not attempt to\n",
     "determine whether or not it is vulnerable."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=133"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0022.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to WhatsUp Gold 8.03 HF 1 if necessary."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (is_cgi_installed3(item: "/_maincfgret.cgi", port:port))
{
  security_hole(port);
  exit(0);
}

if (is_cgi_installed(item:"_maincfgret.cgi", port:port)) 
 security_hole(port);
