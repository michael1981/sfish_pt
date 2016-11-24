#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10317);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0149");
 script_bugtraq_id(373);
 script_xref(name:"OSVDB", value:"247");
 
 script_name(english:"IRIX wrap CGI Traversal Arbitrary Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to
information disclosure." );
 script_set_attribute(attribute:"description", value:
"The 'wrap' CGI is installed.  This CGI allows anyone to get a listing
for any directory with mode +755. 

Note that not all implementations of 'wrap' are vulnerable." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/bugtraq/1997/Apr/0076.html" );
 script_set_attribute(attribute:"solution", value:
"Remove this CGI script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/wrap");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"wrap");
if(res)security_warning(port);

