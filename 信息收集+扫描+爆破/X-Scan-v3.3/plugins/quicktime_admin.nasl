#
# (C) Tenable Network Security, Inc.
#

# Original plugin was written by Michael Scheidell
#
# http://web.archive.org/web/20050406013934/http://www.atstake.com/research/advisories/2003/a022403-1.txt


include("compat.inc");

if(description)
{
 script_id(11278);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2003-0050", "CVE-2003-0051", "CVE-2003-0052", "CVE-2003-0053",
               "CVE-2003-0054", "CVE-2003-0055", "CVE-2003-1414");
 script_bugtraq_id(6954, 6955, 6956, 6957, 6958, 6960, 6990);
 script_xref(name:"OSVDB", value:"9198");
 script_xref(name:"OSVDB", value:"9342");
 script_xref(name:"OSVDB", value:"9343");
 script_xref(name:"OSVDB", value:"10562");
 script_xref(name:"OSVDB", value:"10563");
 script_xref(name:"OSVDB", value:"10564");
 
 script_name(english:"Apple QuickTime/Darwin Streaming Server Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple QuickTime Streaming Server.

There are multiple flaws in this version :

* Remote code execution vulnerability (by default with root privileges)
* 2 Cross Site Scripting vulnerabilies
* Path Disclosure vulnerability
* Arbitrary Directory listing vulnerability 
* Buffer overflow in MP3 broadcasting module" );
 script_set_attribute(attribute:"see_also", value:"http://www.atstake.com/research/advisories/2003/a022403-1.txt" );
 script_set_attribute(attribute:"solution", value:
"Install patches from Apple or disable access to this service." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 

script_end_attributes();

 
 script_summary(english:"Checks QuickTime/Darwin server for parse_xml.cgi");
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl","no404.nasl");
 script_require_ports("Services/www", 1220);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( thorough_tests )
{
 extra_list = make_list ("/AdminHTML");
}
else
  extra_list = NULL;

http_check_remote_code (
			default_port:1220,
			extra_dirs: extra_list,
			check_request:"/parse_xml.cgi?action=login&filename=frameset.html|id%00|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			xss: 1
			);
