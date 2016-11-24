#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36020);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-0819");
  script_bugtraq_id(33972);
  script_xref(name:"OSVDB", value:"52453");
  script_xref(name:"Secunia", value:"34115");

  script_name(english:"MySQL 6.0 < 6.0.10 XPath Expression DoS");
  script_summary(english:"Checks version of MySQL 6.0 Server");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote database server is affected by a denial of service\n",
      "vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of MySQL 6.0 installed on the remote host is earlier than\n",
      "6.0.10 and thus affected by a denial of service vulnerability.\n",
      "Specifically, an authenticated user can cause an assertion failure\n",
      "leading to a server crash by calling 'ExtractValue()' or 'UpdateXML()'\n",
      "using an XPath expression employing a scalar expression as a\n",
      "'FilterExpr'."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://bugs.mysql.com/bug.php?id=42495"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://dev.mysql.com/doc/refman/6.0/en/news-6-0-10.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MySQL Community Server version 6.0.10 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
  version = mysql_get_version();

  if (
    "Community" >< variant && 
    strlen(version) &&
    version =~ "^6\.0\.[0-9]($|[^0-9])"
  )
  {
    if (report_verbosity > 0)
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
