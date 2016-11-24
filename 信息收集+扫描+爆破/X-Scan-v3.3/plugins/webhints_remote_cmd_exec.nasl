#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: blahplok yahoo com
# This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/13/2009)

include("compat.inc");

if(description)
{
 script_id(18478);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2005-1950");
 script_bugtraq_id(13930);
 script_xref(name:"OSVDB", value:"17287");
  
 script_name(english:"WebHints hints.pl Arbitrary Command Execution");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the WebHints scripts.

This version of WebHints has a remote command execution vulnerability
in hints.pl.  A remote attacker could exploit this to execute
arbitrary commands on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0070.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution at this time.  Remove this script from the
web server."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
 script_summary(english:"Checks for WebHints remote command execution flaw");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/hints.pl?|id|",
			extra_check:"WebHints [0-9]+\.[0-9]+</A></SMALL></P></CENTER>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
