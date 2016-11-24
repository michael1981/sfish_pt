#
# (C) Tenable Network Security, Inc.
#

#
# Source: cross_site_scripting.nasl
#


include("compat.inc");

if (description)
{
 script_id(11634);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2003-0292");
 script_bugtraq_id(7596);
 script_xref(name:"OSVDB", value:"6795");

 script_name(english:"Proxy Web Server XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is prone to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a proxy web server that fails to adequately
sanitize request strings of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 script_summary(english:"Determine if the remote proxy is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", "Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:8080);
foreach port (ports)
{
dir[0] = ".jsp";
dir[1] = ".shtml";
dir[2] = ".thtml";
dir[3] = ".cfm";
dir[4] = "";

if(get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
    url = string("http://xxxxxxxxxxx./<SCRIPT>alert('Vulnerable')</SCRIPT>", dir[i]);
    
    confirmtext = string("<SCRIPT>alert('Vulnerable')</SCRIPT>"); 
    r = http_send_recv3(method:"GET", item:url, port:port);
    if(confirmtext >< r[2])
      {
       security_warning(port);
       set_kb_item(name:string("www_proxy/", port, "/generic_xss"), value:TRUE);
       break;
      }
   else break;
  }
 }
}

