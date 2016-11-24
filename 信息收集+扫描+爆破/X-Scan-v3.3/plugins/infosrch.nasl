#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10128);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2000-0207");
 script_bugtraq_id(1031);
 script_xref(name:"OSVDB", value:"102");

 script_name(english:"SGI InfoSearch infosrch.cgi fname Parameter Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a remote command execution vulnerabiltiy." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting the 'infosrch.cgi' script. The
installed version of this script fails to properly sanitize user
supplied input to the 'fname' variable. An attacker, exploiting this
flaw, could execute arbitrary commands on the remote host subject to
the privileges of the web server user." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-03/0001.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches from the vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/infosrch.cgi");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/infosrch.cgi?cmd=getdoc&db=man&fname=|/bin/id",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
