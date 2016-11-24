#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11750);
 script_bugtraq_id(6607);
 script_version ("$Revision: 1.6 $");
  script_name(english:"Psunami.CGI Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is hosting Psunami.CGI
There is a flaw in this CGI which allows an attacker to execute 
arbitrary commands with the privileges of the HTTP server by making a
request like :
	
	/psunami.cgi?action=board&board=1&topic=|id|" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this CGI." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english:"Checks for Psunami.CGI");
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			extra_dirs:make_list("/shop"),
			check_request:"/psunami.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
