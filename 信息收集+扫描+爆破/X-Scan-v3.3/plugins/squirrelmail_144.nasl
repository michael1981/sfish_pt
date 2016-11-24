#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)

include("compat.inc");

if (description) {
  script_id(16228);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
  script_bugtraq_id(12337);
  script_xref(name:"OSVDB", value:"13145");
  script_xref(name:"OSVDB", value:"13146");
  script_xref(name:"OSVDB", value:"13147");
 
  script_name(english:"SquirrelMail < 1.4.4 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of SquirrelMail whose
version number suggests it is affected by one or more cross-site
scripting vulnerabilities :

- Insufficient escaping of integer variables in webmail.php allows a
remote attacker to include HTML / script into a SquirrelMail webpage
(affects 1.4.0-RC1 - 1.4.4-RC1). 

- Insufficient checking of incoming URL vars in webmail.php allows an
attacker to include arbitrary remote web pages in the SquirrelMail
frameset (affects 1.4.0-RC1 - 1.4.4-RC1). 

- A recent change in prefs.php allows an attacker to provide a
specially crafted URL that could include local code into the
SquirrelMail code if and only if PHP's register_globals setting is
enabled (affects 1.4.3-RC1 - 1.4.4-RC1). 
 
***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Squirrelmail 
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.4.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
  summary["english"] = "Checks for Three XSS Vulnerabilities in SquirrelMail < 1.4.4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for 3 XSS vulnerabilities in SquirrelMail < 1.4.3 on port ", port, ".");


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^1\.4\.([0-3](-RC.*)?|4-RC1)$", string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
