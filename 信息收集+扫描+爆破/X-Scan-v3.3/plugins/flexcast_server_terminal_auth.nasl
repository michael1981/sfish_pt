#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18429);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1897");
  script_bugtraq_id(13858);
  script_xref(name:"OSVDB", value:"17126");

  script_name(english:"FlexCast Server Terminal Authentication Unspecified Remote Issue");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia streaming application that is
affected by an authentication vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FlexCast, an audio/video streaming server. 

According to its banner, the version installed on the remote host
suffers from a vulnerability in suppliers / terminal authentication. 
While details are as-yet unavailable, it is likely the flaw is
remotely exploitable." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/apps/freshmeat/2005-05/0021.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FlexCast 2.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for terminal authentication vulnerability in FlexCast Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8000);


# Check the version number in the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  banner =~ "^Server: FlexCast Server/[01]\."
) {
  security_hole(port);
}
