#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10368);
 script_cve_id("CVE-2000-0252", "CVE-2000-0253", "CVE-2000-0254");
 script_bugtraq_id(1115);
 script_version ("$Revision: 1.21 $");

 script_name(english:"Dansie Shopping Cart Backdoor Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The script /cart/cart.cgi is present.

If this shopping cart system is the Dansie Shopping Cart, and if it is 
older than version 3.0.8 then it is very likely that it contains a 
backdoor which allows anyone to execute arbitrary commands on this 
system." );
 script_set_attribute(attribute:"solution", value:
"Use another cart system." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of Dansie Shopping Cart";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res  = is_cgi_installed3(item:"/cart/cart.cgi", port:port);
if( res )security_hole(port);


