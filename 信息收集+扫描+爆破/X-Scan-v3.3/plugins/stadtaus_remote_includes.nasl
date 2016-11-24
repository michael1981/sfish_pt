#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17285);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0678");
  script_bugtraq_id(12735);
  script_xref(name:"OSVDB", value:"14572");

  script_name(english:"Stadtaus PHP Form Mail formmail.inc.php Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include flaw." );
 script_set_attribute(attribute:"description", value:
"There is a version of Form Mail Script, a PHP script by Ralf Stadtaus,
installed on the remote host that suffers from a remote file include
vulnerability involving the 'script_root' parameter of the
'inc/formmail.inc.php' script.  By leveraging this flaw, an attacker
may be able to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts if PHP's
'register_globals' setting is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0083.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.stadtaus.com/forum/p-5887.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Form Mail Script version 2.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detects file include vulnerabilities in Stadtaus' PHP Scripts";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


foreach dir (make_list(cgi_dirs())) {
  # Try to exploit the form to grab the mail template.
  req = http_get(item:string(dir, "/inc/formmail.inc.php?script_root=../templates/mail.tpl.txt%00"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # It's a problem if...
  if (
    # we get the template back or...
     'From: "{firstname} {lastname}" <{email}>' >< res  ||
    # magic_quotes_gpc=1 prevented us from opening the file.
    egrep(pattern:"<b>Warning</b>:  main\(\.\./templates/mail\.tpl\.txt\\0inc/functions\.inc\.php\)", string:res)
  ) {
    security_warning(port);
    exit(0);
  }
}
