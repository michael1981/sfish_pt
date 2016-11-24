#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36216);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1239", "CVE-2009-1905", "CVE-2009-1906");
  script_bugtraq_id(34650, 35171);
  script_xref(name:"OSVDB", value:"54698");
  script_xref(name:"OSVDB", value:"54913");
  script_xref(name:"OSVDB", value:"54914");

  script_name(english:"DB2 9.1 < Fix Pack 7 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installed version of DB2 server is older
than 9.1 Fix Pack 7. Such versions are reportedly affected by multiple
issues :

  - In certain situations an INNER JOIN predicate is applied
    before the OUTER JOIN predicate, which could result in 
    disclosure of sensitive information. (JR31886)

  - It may be possible to connect to DB2 servers without
    valid passwords, provided LDAP-based authentication
    is used, and the remote LDAP server is configured to
    allow anonymous binds. (JR32272)

  - By connecting to a DB2 server using a third-party DRDA
    client that uses IPV6 address format of the correlation
    token, it may be possible to crash the remote DB2
    server. (IZ36683)" );

 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21255607#7");
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR31886" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR32272");
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ36683");

 script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9.1 Fix Pack 7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}


port = get_kb_item("Services/db2das");
if (!port) port = 523;
if (!get_port_state(port)) exit(0);


# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(0);
close(soc);


function is_level_older(lvl, base, min)
{
  if (isnull(lvl) || isnull(base)) return NULL;

  local_var i, v1, v2, vmin;

  v1 = split(lvl, sep:'.', keep:0);
  v2 = split(base, sep:'.', keep:0);
  if (isnull(min)) vmin = make_list(0,0,0,0);
  else vmin = split(min, sep:'.', keep:0);

  v1 = make_list(int(v1[0]), int(v1[1]), int(v1[2]), int(v1[3]));
  v2 = make_list(int(v2[0]), int(v2[1]), int(v2[2]), int(v2[3]));
  vmin = make_list(int(vmin[0]), int(vmin[1]), int(vmin[2]), int(vmin[3]));

  for (i=0; i<max_index(v1); i++)
    if (v1[i] < v2[i])
    {
      if (v1[i] < vmin[i]) return FALSE;
      else return TRUE;
    }
    else if (v1[i] > v2[i]) return FALSE;

  return FALSE;
}

platform = get_kb_item("DB2/" + port + "/Platform");
level = get_kb_item("DB2/" + port + "/Level");
if (platform && level)
{
  if (
    # Windows, x86
    (
      platform == 5 && 
      is_level_older(lvl:level, base:"9.1.700.855", min:"9.0.0.0")
    ) ||
    # Linux, x86, 2.6 kernel
    (
      platform == 18 && 
      is_level_older(lvl:level, base:"9.1.0.7", min:"9.0.0.0")
    )
  ) security_warning(port);
}
