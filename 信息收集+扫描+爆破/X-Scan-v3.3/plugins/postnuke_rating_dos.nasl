#
# (C) Tenable Network Security
#

# Note: Based on the proof of concept example,  NOT fully tested
#
# Reference: http://www.example.com/modules.php?op=modload&name=Downloads&file=index&req=addrating&ratinglid=[DOWNLOAD ID]&ratinguser=[REMOTE USER]&ratinghost_name=[REMOTE HOST ;-)]&rating=[YOUR RANDOM CONTENT] 
#


include("compat.inc");

if (description)
{
 script_id(11676);
 script_version("$Revision: 1.13 $"); 
 script_bugtraq_id(7702);
 script_xref(name:"OSVDB", value:"5500");

 script_name(english:"PostNuke Rating System DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke. PostNuke Phoenix 0.721, 0.722 and
0.723 allows a remote attacker causes a denial of service to legitmate
users, by submitting a string to its rating system." );
 script_set_attribute(attribute:"solution", value:
"Add vendor supplied patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to the PostNuke rating DoS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^0\.([0-6]\.|7\.([0-1]\.|2\.[0-3]))", string:version)) 
	security_warning(port);
