#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29346);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-5969", "CVE-2007-6303", "CVE-2007-6304");
  script_bugtraq_id(26765, 26832);
  script_xref(name:"OSVDB", value:"42608");
  script_xref(name:"OSVDB", value:"42609");
  script_xref(name:"OSVDB", value:"42610");

  script_name(english:"MySQL Enterprise Server 5.0 < 5.0.52 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL Enterprise Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by several issues." );
 script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Server 5.0 installed on the remote
host is earlier than 5.0.52.  Such versions reportedly are affected by
the following issues :

  - Using RENAME TABLE against a table with explicit DATA
    DIRECTORY and INDEX DIRECTORY options can be used to
    overwrite system table information. (Bug #32111).

  - ALTER VIEW retained the original DEFINER value, even 
    when altered by another user, which could allow that 
    user to gain the access rights of the view. (Bug
    #29908)

  - When using a FEDERATED table, the local server can be 
    forced to crash if the remote server returns a result 
    with fewer columns than expected. (Bug #29801)" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/32111" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/29908" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/29801" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-es-5-0-52.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Server version 5.0.52 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P" );
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


port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);


if (mysql_open(soc:soc) == 1)
{
  variant = mysql_get_variant();
  ver = mysql_get_version();

  if ("Enterprise " >< variant && ver =~ "^5\.0\.([0-9]|[1-4][0-9]|5[01])($|[^0-9])")
  {
    report = string(
      "\n",
      "The remote MySQL ", variant, "'s version is :\n",
      "\n",
      "  ", ver, "\n"
    );
    security_warning(port:port, extra:report);
  }
}
mysql_close();
