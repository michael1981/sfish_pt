#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: ZetaLabs, Zone-H Laboratories
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/16/009)


include("compat.inc");

if(description)
{
 script_id(15750);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2275");
 script_bugtraq_id(10626);
 script_xref(name:"OSVDB", value:"7461");
 script_xref(name:"Secunia", value:"11972"); 
 script_name(english:"Webman I-Mall i-mall.cgi Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI script that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The script i-mall.cgi is installed.  Some versions of this script are
vulnerable to remote command execution flaw, due to insufficient user
input sanitization to the 'p' parameter of the i-mall.cgi script.
A malicious user can pass arbitrary shell commands on the remote 
server through this script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/exploits/5UP0715FPC.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Checks for the presence of i-mall.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');


if ( thorough_tests )
{
 extra_list = make_list ("/i-mall");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/i-mall.cgi?p=|id|",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id" );
