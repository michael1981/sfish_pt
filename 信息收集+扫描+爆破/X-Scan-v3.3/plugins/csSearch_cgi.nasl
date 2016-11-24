#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10924);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0495");
 script_bugtraq_id(4368);
 script_xref(name:"OSVDB", value:"761");

 script_name(english:"csSearch csSearch.cgi setup Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/csSearch.cgi");
 
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
     "The version of csSearch running on the remote host has a command\n",
     "execution vulnerability.  Input to the 'print' parameter of\n",
     "'csSearch.cgi' is not properly sanitized.  A remote attacker could\n",
     "exploit this by executing arbitrary system commands with the\n",
     "privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the web server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

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
			check_request:"/csSearch.cgi?command=savesetup&setup=print%20`id`",
			extra_check:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
