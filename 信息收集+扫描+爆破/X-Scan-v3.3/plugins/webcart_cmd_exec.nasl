#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# References:
# Date:  Fri, 19 Oct 2001 03:29:24 +0000
# From: root@xpteam.f2s.com
# To: bugtraq@securityfocus.com
# Subject: Webcart v.8.4

include( 'compat.inc' );

if(description)
{
  script_id(11095);
  script_version ("$Revision: 1.17 $");
  script_cve_id("CVE-2001-1502");
  script_bugtraq_id(3453);
  script_xref(name:"OSVDB", value:"2087");

  script_name(english:"Mountain Network Systems webcart.cgi Arbitrary Command Execution");
  script_summary(english:"Detects webcart.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote CGI script is vulnerable to command execution."
  );

  script_set_attribute(
    attribute:'description',
    value:"webcart.cgi is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade your software or firewall your web server."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://archives.neohapsis.com/archives/bugtraq/2001-10/0159.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( thorough_tests )
{
 extra_list = make_list ("/webcart", "/cgi-bin/webcart");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/webcart.cgi?CONFIG=mountain&CHANGE=YES&NEXTPAGE=;id|&CODE=PHOLD",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id"
			);
