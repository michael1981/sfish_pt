#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11567);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2003-1481");
 script_bugtraq_id(7501);
 script_xref(name:"OSVDB", value:"50621");

 script_name(english:"CommuniGate Pro Referer Field Session Token Disclosure");
 script_summary(english:"Checks the version of the remote CommunigatePro web Server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote service has a session hijacking vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:string(
     "The remote install of CommuniGate Pro, according to its version\n",
     "number, is vulnerable to a flaw which may allow a remote attacker to\n",
     "access the mailbox of a targeted user.\n",
     "\n",
     "To exploit such a flaw, an attacker needs to send an email to its\n",
     "victim with a link to an image hosted on a rogue server which will\n",
     "store the Referer field sent by the user user-agent which contains\n",
     "the credentials used to access the victim's mailbox."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-05/0060.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to CommuniGate Pro version 4.1b2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencies("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: CommuniGatePro/([0-3]\.|4\.0|4\.1b1)", string:banner))security_warning(port);

