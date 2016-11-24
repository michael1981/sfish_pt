#
# (C) Tenable Network Security, Inc.
#
# osvdb value submitted by David Maciejak


include("compat.inc");

if (description) {
  script_id(14237);
  script_bugtraq_id(10853);
  script_xref(name:"OSVDB", value:"8935");
  script_version ("$Revision: 1.9 $");

  script_name(english:"Goscript go.cgi Arbitrary Command Execution");
  script_summary(english:"Goscript command execution detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is affected by a remote
command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GoScript. The installed version fails to
proerly sanitize user supplied input to the 'go.cgi' script. An
unauthenticated remote attacker could exploit this flaw to execute
arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0037.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			check_request:"/go.cgi|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
