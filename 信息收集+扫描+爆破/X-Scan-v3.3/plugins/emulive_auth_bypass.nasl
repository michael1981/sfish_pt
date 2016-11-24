#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14805);
 script_cve_id("CVE-2004-1695", "CVE-2004-1696");
 script_bugtraq_id(11226);
 script_xref(name:"OSVDB", value:"10176");
 script_xref(name:"OSVDB", value:"10177");
 script_version ("$Revision: 1.5 $");

 script_name(english:"Emulive Server4 Authentication Bypass");
 script_summary(english:"Requests the admin page of the remote EmuLive Server4");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an authentication\n",
     "bypass vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running EmuLive Server4, a web and media streaming\n",
     "server.\n\n",
     "There is a flaw in the administrative interface that allows a remote\n",
     "attacker to bypass the authentication procedure by requesting the page\n",
     "'/public/admin/index.htm' directly.\n\n",
     "An attacker may exploit this flaw to gain administrative access over\n",
     "the remote service.\n\n",
     "Emulive has also been reported to have a denial of service condition\n",
     "when handling carriage returns, though Nessus has not checked for this\n",
     "issue."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0251.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
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
 script_require_ports("Services/www", 81);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:81);
res = http_send_recv3(method:"GET", item:"/PUBLIC/ADMIN/INDEX.HTM", port:port);
if (isnull(res)) exit(0);

if (
  "Emulive Server4" >< res[2] &&
  "<title>Server4 Administration Console</title>" >< res[2]
) security_hole(port);
