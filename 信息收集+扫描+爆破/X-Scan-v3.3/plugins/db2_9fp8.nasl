#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42044);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3471", "CVE-2009-3472", "CVE-2009-3473"); 
  script_bugtraq_id(36540);
  script_xref(name:"OSVDB", value:"58477");
  script_xref(name:"OSVDB", value:"58478");
  script_xref(name:"OSVDB", value:"58479");
  script_xref(name:"Secunia", value:"36890");

  script_name(english:"DB2 9.1 < Fix Pack 8 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installed version of DB2 server is older
than 9.1 Fix Pack 8.  Such versions are reportedly affected by
multiple issues :

  - MODIFIED SQL DATA table function is not dropped even if 
    the maintainer does not have privileges to maintain the 
    objects. (IZ46773)

  - It may be possible for an unauthorized user to insert,
    update, or delete rows in a table. (IZ50078)
 
  - An user without 'SETSESSIONUSER' privilege can perform
    'SET SESSION AUTHORIZATION'. (IZ55883)" );

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");

  script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9.1 Fix Pack 8 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");

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
if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");


# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't a open socket to TCP port "+port+".");
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
if (isnull(platform)) exit(1, "The 'DB2/"+port+"/Platform' KB item is missing.");
level = get_kb_item("DB2/" + port + "/Level");
if (isnull(platform)) exit(1, "The 'DB2/"+port+"/Level' KB item is missing.");

if (
  # Windows, x86
  (
    platform == 5 && 
    is_level_older(lvl:level, base:"9.1.800.1023", min:"9.0.0.0")
  ) ||
  # Linux, x86, 2.6 kernel
  (
    platform == 18 && 
    is_level_older(lvl:level, base:"9.1.0.8", min:"9.0.0.0")
  )
) security_warning(port);
else exit(0, "The installed DB2 platform / level are "+platform+" / "+level+" and thus not affected.");
