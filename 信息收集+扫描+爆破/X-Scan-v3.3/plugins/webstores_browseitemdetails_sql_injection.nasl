#
# (C) Tenable Network Security, Inc.



include("compat.inc");

if(description)
{
 script_id(11692);
 script_cve_id("CVE-2004-0304");
 script_bugtraq_id(7766);
 script_version("$Revision: 1.15 $");
 name["english"] = "WebStores 2000 browse_item_details.asp SQL injection";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running WebStore 2000, a set of ASP scripts
designed to set up an e-commerce store. 

There is a flaw in the version of WebStore used on the remote host
that may allow an attacker to make arbitrary SQL statements to the
backend database.  An attacker may be able to exploit this issue to
add administrative accounts, execute arbitrary commands using the
'xp_cmdshell' function, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=107712159425226&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


 summary["english"] = "WebStores 2000 SQL injection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 r = http_send_recv3(port:port, method: 'GET',
  item:string(dir, "/browse_item_details.asp?Item_ID='", SCRIPT_NAME));
 if (isnull(r)) exit(0);
 
 if(r[0] =~ "^HTTP/[0-9]\.[0-9] +200 " && 
    "Microsoft OLE DB Provider" >< r[2])
    {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit (0);
    }
}
