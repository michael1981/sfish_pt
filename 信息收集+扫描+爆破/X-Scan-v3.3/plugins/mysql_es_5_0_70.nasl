#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34727);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-4098");

  script_name(english:"MySQL Enterprise Server 5.0 < 5.0.70 Privilege Bypass");
  script_summary(english:"Checks version of MySQL Enterprise Server 5.0");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a privilege bypass
attack." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Server 5.0 installed on the remote
host is earlier than 5.0.70.  In such versions, it is possible for a
local user to circumvent privileges through the creation of MyISAM
tables employing the 'DATA DIRECTORY' and 'INDEX DIRECTORY' options to
overwrite existing table files in the application's data directory. 

Note that this issue was supposed to have been addressed in version
5.0.60, but the fix was incomplete." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=32167" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-es-5-0-70.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/09/20" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/16/3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise version 5.0.70 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );
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
    "Enterprise " >< variant && 
    strlen(version) && 
    version =~ "^5\.0\.([0-9]|[1-6][0-9])($|[^0-9])"
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote MySQL ", variant, "'s version is :\n",
        "\n",
        "  ", version, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();
