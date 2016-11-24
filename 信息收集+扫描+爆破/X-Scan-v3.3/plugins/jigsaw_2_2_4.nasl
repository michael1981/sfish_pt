#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12071);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2274");
 script_bugtraq_id(9711);
 script_xref(name:"OSVDB", value:"4014");

 script_name(english:"Jigsaw < 2.2.4 Unspecified URI Parsing Vulnerability");
 script_summary(english:"Checks for version of Jigsaw");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an unspecified vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its banner, the remote version of Jigsaw web server has\n",
     "an unspecified vulnerability related to the way it parses URIs.\n"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.w3.org/Jigsaw/RelNotes.html#2.2.4"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Jigsaw 2.2.4 or later."
 );
 # details of this vuln are unknown...we'll assume worst case scenario
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" 
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if(!banner)exit(0);
 
if(egrep(pattern:"^Server: Jigsaw/([01]\.|2\.([01]\.|2\.[0-3][^0-9])).*", string:banner))
 {
   security_hole(port);
 }
