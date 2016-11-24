#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(15935);
  script_cve_id("CVE-2004-2500");
  script_bugtraq_id(11872);
  script_xref(name:"OSVDB", value:"12292");
  script_version("$Revision: 1.7 $");

  script_name(english:"IlohaMail Unspecified Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an unspecified vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of IlohaMail version
0.8.13 or earlier.  Such versions are reportedly affected by an
unspecified vulnerability." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?group_id=54027&release_id=288409" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.14RC1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks  IlohaMail version";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

kb = get_kb_list("www/" + port + "/ilohamail");
if (isnull( kb )) exit(0);


foreach item (kb) 
{
  matches = eregmatch(string:item, pattern:"^(.+) under (.*)$");
  if ( ereg(pattern:"^0\.([0-7]\.|8\.([0-9][^0-9]|1[0-3]))", string:matches[1]) )
	{
	security_hole(port);
	exit(0);
	}
}
