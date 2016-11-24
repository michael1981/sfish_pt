#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10285);
 script_bugtraq_id(1248);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0359");
 
 script_name(english:"thttpd 2.04 If-Modified-Since Header Remote Buffer Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote thttpd server execute
arbitrary code by sending a request like :

	GET / HTTP/1.0
	If-Modified-Since: AAA[...]AAAA
	
An attacker may use this to gain control on your computer." );
 script_set_attribute(attribute:"solution", value:
"If you are using thttpd, upgrade to version 2.05. 
If you are not, then contact your vendor and ask for 
a patch, or change your web server" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "thttpd buffer overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "www_too_long_url.nasl", "http_version.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("www/thttpd");
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

if(safe_checks())
{
 banner = get_http_banner(port: port);
  if(banner)
  {
    if(egrep(pattern:"^Server: thttpd/2\.0[0-4]",string:banner))
    { 
      if (report_verbosity > 0)
      { 
         report = string(
                  "\n",
                  "The remote server responded with the following banner : ","\n\n",
                  banner,"\n\n",
                  "Note that Nessus only checked the version in the banner because safe\n",
                  "checks were enabled for this scan.\n"
                );
          security_hole(port:port, extra:report);
      }
      else
        security_hole(port);
        exit(0);
    }
  }
}
else
{ 
  if(http_is_dead(port:port))exit(0, "The remote host is dead.");

  res = http_send_recv3(method:"GET", item:"/", port:port);
  if(isnull(res)) exit(1, "The remote web server failed to respond.");

  res = http_send_recv3(method:"GET", item:"/", port:port,
         add_headers: make_array("If-Modified-Since",crap(1500)));

  if(http_is_dead(port:port))security_hole(port);
}
