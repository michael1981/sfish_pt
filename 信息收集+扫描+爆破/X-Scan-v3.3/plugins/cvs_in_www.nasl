#
# This script was written by Nate Haggard (SecurityMetrics inc.)
#
# See the Nessus Scripts License for details

# Changes by Tenable:
# - pattern matching to determine if the file is CVS indeed [RD]
# - Revised title (12/22/08)
# - Output formatting (8/21/09)


include("compat.inc");

if(description)
{
 script_id(10922);
 script_version ("$Revision: 1.15 $");

 script_name(english:"CVS (Web Based) Entries File Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CVS repository that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Your website allows read access to the CVS/Entries file.  This exposes
all file names in your CVS module on your website.  Change your 
website permissions to deny access to your CVS directory." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to CVS." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"requests CVS/Entries");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Nate Haggard (SecurityMetrics inc.)");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404") ) exit(0);

res = is_cgi_installed_ka(item:"/CVS/Entries", port:port);
# is_cgi_installed_ka takes care of servers that always return 200
# This was tested with nessus 1.2.1 
if(res)
{
 if (debug_level) display("cvs_in_www.nasl: ", res, "\n");

 soc = http_open_socket(port);
 file = string("/CVS/Entries");
 req = http_get(item:file, port:port);
 send(socket:soc, data:req);
 h = http_recv_headers2(socket:soc);
 r = http_recv_body(socket:soc, headers:h, length:0);
 http_close_socket(soc);

 warning += string("\n", "The CVS directory entries contains the following: \n", r);

  security_warning(port:port, extra:warning);
}
exit(0);
