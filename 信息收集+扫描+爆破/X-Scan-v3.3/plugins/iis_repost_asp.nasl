#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#

include("compat.inc");

if(description)
{
 script_id(10372);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-1999-0360");
 script_bugtraq_id(1811);
 script_xref(name:"OSVDB", value:"285");

 script_name(english:"Microsoft IIS repost.asp File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server supports arbitrary file uploads." );
 script_set_attribute(attribute:"description", value:
"The script '/scripts/repost.asp' is installed on the remote IIS web
server and allows an attacker to upload arbitrary files to the
'/Users' directory if it has not been configured properly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0413.html" );
 script_set_attribute(attribute:"solution", value:
"Create the '/Users' directory if necessary and ensure that the
Anonymous Internet Account ('IUSER_MACHINE') only has read access to
it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Determines whether /scripts/repost.asp is present";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function test_cgi(port, cgi, output)
{
 local_var w, r, soc;

 w = http_send_recv3(method:"GET", item:cgi, port:port);
 if (isnull(w)) return 0;
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(output >< r)
  {
  	security_hole(port);
	exit(0);
  }
 return(0);
}
 
 

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

test_cgi(port:port, cgi:"/scripts/repost.asp", output:"Here is your upload status");
