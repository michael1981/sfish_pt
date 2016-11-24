#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25242);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-2693");
  script_bugtraq_id(23911, 24008, 24011, 24016);
  script_xref(name:"OSVDB", value:"34734");
  script_xref(name:"OSVDB", value:"34765");
  script_xref(name:"OSVDB", value:"34766");
  script_xref(name:"OSVDB", value:"37781");

  script_name(english:"MySQL 5.1 < 5.1.18 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly is
affected by several issues :

  - Evaluation of an 'IN()' predicate with a decimal-valued
    argument causes a service crash.

  - A user can rename a table even though he does not have 
    DROP privileges.

  - If a stored routine is declared as 'SQL SECURITY INVOKER', 
    a user may be able to gain privileges by invoking that 
    routine.

  - A user with only ALTER privileges on a partitioned table
    can discover information about the table that should 
    require SELECT privileges." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=23675" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27515" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27337" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-18.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.1.18 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P" );
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
  ver = mysql_get_version();
  if (isnull(ver)) exit(0);

  if (ver =~ "^5\.1\.([0-9]($|[^0-9])|1[1-7]($|[^0-9]))")
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
