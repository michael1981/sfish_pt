#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40662);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-2858", "CVE-2009-2859", "CVE-2009-2860");
  script_bugtraq_id(36059);
  script_xref(name:"OSVDB", value:"57229");
  script_xref(name:"OSVDB", value:"57230");
  script_xref(name:"OSVDB", value:"57231");
  script_xref(name:"OSVDB", value:"57232");
  script_xref(name:"OSVDB", value:"57233");
  script_xref(name:"Secunia", value:"36313");

  script_name(english:"DB2 8.1 < Fix Pack 18 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );

  script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 8.1 on the remote
host is affected by one or more of the following issues :

  - It may be possible for a local attacker to gain 
    unauthorized access using the 'DAS' command. 
    (IZ34149)

  - It may be possible to crash the server by sending
    specially crafted packets to the 'DB2JDS' service. 
    (IZ52433)

  - The security component in UNIX installs is affected 
    by a private memory leak. (IZ35635)" );

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507237/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21255352" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ34149" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ52433" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ35635" );

  script_set_attribute(attribute:"solution", value:
"Apply DB2 UDB Version 8.1 FixPak 18 or later." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);
  exit(0);
}

#

port = get_kb_item("Services/db2das");
if (!port) port = 523;
if (!get_port_state(port)) exit(0);

# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(1, "DB2 port not open.");
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
    (platform ==  5 && is_level_older(lvl:level, base:"8.1.18.980")) ||
    # Linux, x86, 2.6 kernel
    (platform == 18 && is_level_older(lvl:level, base:"8.1.2.160"))
  ) security_warning(port);
}
