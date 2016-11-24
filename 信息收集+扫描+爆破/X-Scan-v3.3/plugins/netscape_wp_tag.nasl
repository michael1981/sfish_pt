#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10352);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2000-0236");
 script_bugtraq_id(1063);
 script_xref(name:"OSVDB", value:"11634");

 script_name(english:"Netscape Server ?wp-* Publishing Tags Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Requesting a URL with special tags such as '?wp-cs-dump' appended to
it makes some Netscape servers dump the listing of the page directory,
thus revealing the existence of potentially sensitive files to an
attacker." );
 script_set_attribute(attribute:"solution", value:
"Disable the 'web publishing' feature of the server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Make a request like http://www.example.com/?wp-cs-dump");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


res = http_get_cache(item:"/", port:port);
if(res == NULL || "<title>index of /</title>" >< tolower(res))exit(0);

tags = make_list("?wp-cs-dump", "?wp-ver-info", "?wp-html-rend", "?wp-usr-prop",
"?wp-ver-diff", "?wp-verify-link", "?wp-start-ver", "?wp-stop-ver", "?wp-uncheckout");

foreach tag (tags)
{
  req = http_get(item:"/" + tag, port:port);
  res = http_keepalive_send_recv(data:req, port:port);
  
  if( res == NULL ) exit(0);
  if("<title>index of /</title>" >< tolower(res)) 
  	{
		security_warning(port);
	}
  
}
