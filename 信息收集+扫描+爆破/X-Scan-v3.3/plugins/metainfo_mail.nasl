#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID


include("compat.inc");


if(description)
{
 script_id(10141);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-1999-0268");
 script_bugtraq_id(110);
 script_xref(name:"OSVDB", value:"110");
 script_xref(name:"OSVDB", value:"3969");

 script_name(english:"MetaInfo Web Server Traversal Arbitrary Command Execution");
 script_summary(english:"Read everything using '../' in the URL");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote host has a command execution vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote MetaInfo web server (installed with MetaInfo's Sendmail or\n",
     "MetaIP servers) has an arbitrary command execution vulnerability.  It\n",
     "is possible to read files or execute arbitrary commands by prepending\n",
     "the appropriate number of '../' to the desired filename.  A remote\n",
     "attacker could exploit this to execute arbitrary commands on the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1998_2/0687.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports(5000);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = 5000;

if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"../smusers.txt", port:port);
  if (isnull(res)) exit(1, "The web server didn't respond");

  rep = res[0] + res[1] + res[2];
  if(" 200 " >< rep)security_hole(port);
}
