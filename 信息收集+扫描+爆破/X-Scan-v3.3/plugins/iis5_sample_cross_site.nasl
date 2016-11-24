#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10572);
 script_version("$Revision: 1.16 $");

 script_xref(name:"OSVDB", value:"470");

 script_name(english:"Microsoft IIS 5.0 Form_JScript.asp XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an ASP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The script /iissamples/sdk/asp/interaction/Form_JScript.asp (of
Form_VBScript.asp) allows you to insert information into a form field
and once submitted re-displays the page, printing the text you
entered. This .asp doesn't perform any input validation. An attacker
can exploit this flaw to execute arbitrary script code in the browser
of an unsuspecting victim." );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2000-02.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the sample scripts from the server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );



script_end_attributes();

 
 summary["english"] = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/Form_JScript.asp", port:port);
if( res )
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}


