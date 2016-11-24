#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11751);
 script_bugtraq_id(7945);
 script_xref(name:"OSVDB", value:"4324");
 script_version ("$Revision: 1.10 $");

 script_name(english:"Dune Web Server GET Request Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Dune Web server which is
older than 0.6.8.

There is a flaw in this software which may be exploited by an attacker
to gain a shell on this host." );
 script_set_attribute(attribute:"solution", value:
"Use another web server or upgrade to Dune 0.6.8" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for Dune Overflow";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);


if( safe_checks() )
{ 
 banner = get_http_banner(port:port);
 if( banner == NULL ) exit(0);
 
 if(egrep(pattern:"^Server: Dune/0\.([0-5]\.|6\.[0-7]$)", string:banner))
  {
   security_hole(port);
  }
  exit(0);
}


banner = get_http_banner(port:port);
if(!banner)exit(0);
if("Dune/" >!< banner)exit(0);

if(http_is_dead(port:port))exit(0);

r = http_send_recv3(method: "GET", item:"/" + crap(51), port:port);
if(! isnull(r))
{
 r = http_send_recv3(method: "GET", item:"/~" + crap(50), port:port);
 if (isnull(r)) security_hole(port);
}
