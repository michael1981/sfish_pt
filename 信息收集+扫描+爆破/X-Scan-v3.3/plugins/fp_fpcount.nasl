#
# (C) Tenable Network Security, Inc.
#

# Added some extra checks. Axel Nennker axel@nennker.de

include("compat.inc");

if(description)
{
 script_id(11370);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-1999-1376");
 script_bugtraq_id(2252);
 script_xref(name:"OSVDB", value:"3500");

 script_name(english:"Microsoft IIS fpcount.exe CGI Remote Overflow");
 script_summary(english:"Is fpcount.exe installed ?");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "Nessus detected the 'fpcount.exe' CGI on the remote web server.  Some\n",
     "versions of this CGI have a remote buffer overflow vulnerability.  A\n",
     "remote attacker could exploit it to crash the web server, or possibly\n",
     "execute arbitrary code.\n\n",
     "*** Nessus did not actually check for this flaw,\n",
     "*** but solely relied on the presence of this CGI\n",
     "*** instead."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0181.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Make sure FPServer Extensions 98 or later is installed."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/_vti_bin/fpcount.exe", port:port);
if (isnull(res)) exit(1, "The server didn't respond.");

res = res[0] + res[1] + res[2];
if(("Microsoft-IIS/4" >< res) && ("HTTP/1.1 502 Gateway" >< res) )
	security_hole(port);
