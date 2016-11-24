#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#


include("compat.inc");

if(description)
{
 script_id(10363);
 script_bugtraq_id(1814);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0253"); 
 script_xref(name:"OSVDB", value:"277");

 script_name(english:"Microsoft IIS/PWS %2e Request ASP Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to get the source code of a remote ASP script by
appending '%2e' to the end of the request.  ASP source code usually
contains sensitive information such as logins and passwords." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "downloads the source of ASP scripts";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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
if (!can_host_asp(port:port)) exit(0);

function check(file)
{
  local_var w, r;

  w = http_send_recv3(method:"GET",item:string(file, "%2e"), port:port);
  if (isnull(w)) exit(0);
  r = strcat(w[0], w[1], '\r\n', w[2]);
  if ("Content-Type: application/octet-stream" >< r && "<%" >< r) {
    security_warning(port);
    return(1);
  }
  return(0);
}

if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]);
