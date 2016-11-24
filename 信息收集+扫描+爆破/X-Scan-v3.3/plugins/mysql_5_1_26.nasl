#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34160);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2008-3963");
  script_bugtraq_id(31081);
  script_xref(name:"OSVDB", value:"48021");

  script_name(english:"MySQL 5.1 < 5.1.26 Empty Bit-String Literal Token SQL Statement DoS");
  script_summary(english:"Checks version of MySQL 5.1 Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.26.  A bug in such versions can lead to a server crash in
'Item_bin_string::Item_bin_string' when handling an empty bit-string
literal (b'').  Using a simple SELECT statement, an authenticated
remote user can leverage this issue to crash the database server and
deny service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=35658" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/09/4" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/09/7" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.1.26." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  version = mysql_get_version();

  if (
    strlen(version) &&
    version =~ "^5\.1\.([0-9]|1[0-9]|2[0-5])($|[^0-9])"
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote MySQL server's version is :\n",
        "\n",
        "  ", version, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();
