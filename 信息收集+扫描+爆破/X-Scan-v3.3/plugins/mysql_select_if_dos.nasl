#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25198);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2583");
  script_bugtraq_id(23911);
  script_xref(name:"OSVDB", value:"34734");

  script_name(english:"MySQL Crafted IF Clause Divide-by-zero NULL Dereference DoS");
  script_summary(english:"Checks version of MySQL");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly is
affected by a denial of service vulnerability that may be triggered
with a specially crafted IF query.  An attacker who can execute
arbitrary SELECT statements may be able to leverage this issue to
crash the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27513" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-es-5-0-40.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Community Server 5.0.41 / 5.1.18 / Enterprise Server
5.0.40 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("global_settings.inc");
include("mysql_func.inc");


# nb: banner checks of open-source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);


if (mysql_open(soc:soc) == 1)
{
  variant = mysql_get_variant();
  ver = mysql_get_version();

  if (
    (
      "Enterprise" >< variant && 
      ver =~ "^5\.0\.([0-9]|[1-3][0-9])($|[^0-9])"
    ) ||
    ver =~ "^5\.(0\.([0-9]|[1-3][0-9])|1\.([0-9]|1[1-7]))($|[^0-9])"
  )
  {
    report = string(
      "The remote MySQL ", mysql_get_variant(), "'s version is :\n",
      "\n",
      "  ", ver, "\n"
    );
    security_warning(port:port, extra:report);
  }
}
mysql_close();
