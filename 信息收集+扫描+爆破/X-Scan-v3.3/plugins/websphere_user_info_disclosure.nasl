#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16173);
  script_version ("$Revision: 1.8 $");
  script_bugtraq_id(11816);
  script_xref(name:"Secunia", value:"13234");
  script_xref(name:"OSVDB", value:"12185");

  script_name(english:"IBM Websphere Commerce Database Update Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Websphere Commerce that
may allow potentially confidential information to be accessed through
the default user account.  An attacker, exploiting this flaw, would
only need to be able to make standard queries to the application
server." );
 script_set_attribute(attribute:"solution", value:
"Contact WebSphere Commerce support to resolve the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );


script_end_attributes();

  summary["english"] = "Detects Websphere default user information leak";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner) exit(0);
# Server: WebSphere Application Server/6.0
if (egrep(string:banner, pattern:"^Server: WebSphere Application Server/([0-4]\.|5\.[0-6][^0-9])"))	
   security_note(port);
