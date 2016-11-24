#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34159);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CVE-2007-5969",
    "CVE-2008-0226",
    "CVE-2008-0227",
    "CVE-2008-2079"
  );
  script_bugtraq_id(26765, 27140, 29106);
  script_xref(name:"OSVDB", value:"42608");

  script_name(english:"MySQL Community Server 5.0 < 5.0.67 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL Community Server 5.0");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by several issues." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server 5.0 installed on the remote host
is before 5.0.66.  Such versions are reportedly affected by the
following issues :

  - When using a FEDERATED table, a local server could be 
    forced to crash if the remote server returns a result 
    with fewer columns than expected (Bug #29801).

  - ALTER VIEW retains the original DEFINER value, even 
    when altered by another user, which could allow that 
    user to gain the access rights of the view (Bug 
    #29908).

  - A local user can circumvent privileges through creation 
    of MyISAM tables using the 'DATA DIRECTORY' and 'INDEX 
    DIRECTORY' options to overwrite existing table files in
    the application's data directory (Bug #32167). 

  - RENAME TABLE against a table with DATA/INDEX DIRECTORY 
    overwrites the file to which the symlink points (Bug
    #32111).

  - It was possible to force an error message of excessive
    length, which could lead to a buffer overflow (Bug 
    #32707).

  - Three vulnerabilities in yaSSL versions 1.7.5 and
    earlier as used in MySQL could allow an unauthenticated
    remote attacker to crash the server or to execute 
    arbitrary code provided yaSSL is enabled and the server
    allows TCP connections (Bug #33814)." );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-67.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/542" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Community Server version 5.0.67." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
  variant = mysql_get_variant();
  version = mysql_get_version();

  if (
    "Community " >< variant && 
    strlen(version) &&
    version =~ "^5\.0\.([0-9]|[1-5][0-9]|6[0-6])($|[^0-9])"
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
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
mysql_close();
