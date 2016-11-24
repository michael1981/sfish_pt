#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15787);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(11727);
 script_xref(name:"OSVDB", value:"12061");

 script_name(english:"WebGUI user profile Unspecified Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that has an unspecified
remote flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebGUI, a content management system from
Plain Black Software. 

According to its banner, the version of this software on the remote is
earlier than 6.2.9 and thus affected by an undisclosed remote
vulnerability related to the 'user profile' feature." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=284011" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebGUI 6.2.9 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 script_summary(english:"Checks the version of WebGUI");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);

if ( 'content="WebGUI' >< res && egrep(pattern:".*meta name=.generator.*content=.WebGUI ([0-5]\.|6\.([01]\.|2\.[0-8][^0-9]))", string:res) )
  security_hole(port);
