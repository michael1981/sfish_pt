#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14634);
  script_bugtraq_id(10668);
  script_xref(name:"OSVDB", value:"51270");

  script_version("$Revision: 1.12 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)

  script_name(english:"IlohaMail Email Header XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of IlohaMail version
0.8.12 or earlier.  Such versions do not properly sanitize message
headers, leaving users vulnerable to XSS attacks.  For example, a
remote attacker could inject JavaScript code that steals the user's
session cookie and thereby gain access to that user's account." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.13 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for Email Header HTML Injection vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    ver = matches[1];

    if (ver =~ "^0\.([0-7].*|8\.([0-9]|1[0-2])(-Devel)?$)")
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
