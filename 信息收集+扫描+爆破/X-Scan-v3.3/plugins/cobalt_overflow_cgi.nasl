#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11190);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2002-1361");
 script_xref(name:"OSVDB", value:"8513");

 script_name(english:"Cobalt RaQ4 Administrative Interface overflow.cgi Command Execution");
 script_summary(english:"Checks for the presence of a CGI");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has a command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
      "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.\n",
      "Some versions of this CGI allow remote users to execute arbitrary\n",
      "commands with the privileges of the web server.\n\n",
      "*** Nessus just checked the presence of this file\n",
      "*** but did not try to exploit the flaw, so this might\n",
      "*** be a false positive"
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cert.org/advisories/CA-2002-35.html"
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
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_hole(port);
