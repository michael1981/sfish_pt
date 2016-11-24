#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19416);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-2558");
  script_bugtraq_id(14509);
  script_xref(name:"OSVDB", value:"18896");

  script_name(english:"MySQL User-Defined Function init_syms() Function Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow flaw." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of MySQL on the
remote host may be prone to a buffer overflow when copying the name of
a user-defined function into a stack-based buffer.  With sufficient
access to create a user-defined function, an attacker may be able to
exploit this and execute arbitrary code within the context of the
affected database server process." );
 script_set_attribute(attribute:"see_also", value:"http://www.appsecinc.com/resources/alerts/mysql/2005-002.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.25 / 4.1.13 / 5.0.7-beta or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks MySQL version number");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_func.inc");


port = get_kb_item("Services/mysql");
if (!port) port = 3306;

soc = open_sock_tcp(port);
if (!soc) exit(0);

if (mysql_open(soc:soc) == 1)
{
  ver = mysql_get_version();
  if (isnull(ver)) exit(0);

  if (
    # ??? ver =~ "^[0-3]\." ||
    # versions 4.0.x less than 4.0.25
    ver =~ "^4\.0\.([0-9]([^0-9]|$)|1[0-9]|2[0-4])" ||
    # versions 4.1.x less than 4.1.6
    ver =~ "^4\.1\.[0-5]([^0-9]|$)" ||
    # versions 5.0.x less than 5.0.5
    ver =~ "^5\.0\.[0-4]([^0-9]|$)"
  ) security_warning(port);
}
