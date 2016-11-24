#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23937);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-6638", "CVE-2007-1228");
  script_bugtraq_id(21646, 22729);
  script_xref(name:"OSVDB", value:"34021");
  script_xref(name:"OSVDB", value:"34022");

  script_name(english:"DB2 < 8.1 FixPak 14 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 on the remote host
may crash when processing specially-crafted SQLJRA packets because it
tries to dereference a NULL pointer in the function
'sqle_db2ra_as_recvrequest'.  A remote attacker can send such packets
without authentication to deny service to legitimate users of the
application. 

In addition, the fenced userid may be able to access directories
without proper authorization." );
 script_set_attribute(attribute:"see_also", value:"http://www.appsecinc.com/resources/alerts/db2/2006-11-30.shtml" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24014043" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IY86711" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 UDB Version 8.1 FixPak 14 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 
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
    (platform == 5 && is_level_older(lvl:level, base:"8.1.13.271")) ||
    # Linux, x86, 2.6 kernel
    (platform == 18 && is_level_older(lvl:level, base:"8.1.2.128"))
  ) security_warning(port);
}
