#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10343);
  script_version ("$Revision: 1.19 $");
  script_cve_id("CVE-2000-0148");
  script_bugtraq_id(975);
  script_xref(name:"OSVDB", value:"261");

  script_name(english:"MySQL Short Check String Authentication Bypass");
  script_summary(english:"Checks for the remote MySQL version");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote MySQL server is vulnerable to an access control breach."
  );

  script_set_attribute(
    attribute:'description',
    value:"You are running a version of MySQL which is  older than
(or as old as) version 3.22.30 or 3.23.10.

If you have not patched this version, then any attacker who knows
a valid username can access your tables without having to enter any
valid password."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to a newer version, or edit the file mysql-xxx/sql/password.c, and
search for the 'while(*scrambled)' loop. In front of it, add :
  'if(strlen(scrambled) != strlen(to))return 1'"
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://archives.neohapsis.com/archives/bugtraq/2000-02/0053.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"Databases");
  script_dependencie("find_service1.nasl", "mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver = get_mysql_version(port:port);
if (ver == NULL) exit(0);
if(ereg(pattern:"^3\.(22\.(2[6789]|30)|23\.([89]|10))", string:ver))security_hole(port);
