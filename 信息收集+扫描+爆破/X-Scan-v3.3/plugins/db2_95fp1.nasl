#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33763);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-1966", "CVE-2008-1997", "CVE-2008-1998", "CVE-2008-3852", "CVE-2008-3854");
  script_bugtraq_id(28835, 28836, 28843);
  script_xref(name:"OSVDB", value:"41631");
  script_xref(name:"OSVDB", value:"41796");
  script_xref(name:"OSVDB", value:"44963");
  script_xref(name:"OSVDB", value:"46263");
  script_xref(name:"OSVDB", value:"46264");
  script_xref(name:"OSVDB", value:"46265");
  script_xref(name:"OSVDB", value:"46266");
  script_xref(name:"OSVDB", value:"46267");
  script_xref(name:"OSVDB", value:"46270");

  script_name(english:"DB2 < 9.5 Fix Pack 1 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installation of DB2 9.5 on the remote host does not have any Fix
Packs applied and thus is affected by one or more of the following
issues :

  - There is a security vulnerability in the 'NNSTAT'
    procedure on Windows platforms only that allows low-
    privileged users to overwrite arbitrary files
    (IZ10776).

  - There is a security vulnerability in the
    'SYSPROC.ADMIN_SP_C' procedure on Windows platforms 
    that allows users to load arbitrary library and 
    execute arbitrary code in the system (IZ10917).

  - An unspecified vulnerability affects 'DB2WATCH' and
    'DB2FREEZE' on Solaris platforms (IZ12994).

  - An authenticated remote user can cause the DB2 instance
    to crash by passing specially crafted parameters to 
    the 'RECOVERJAR' and 'REMOVE_JAR' procedures (IZ15496).

  - There is an internal buffer overflow vulnerability in
    the DAS process that could allow arbitrary code 
    execution on the affected host (IZ12406).

  - A local attacker can create arbitrary files as root 
    on Unix and Linux platforms using symlinks to the 
    'dasRecoveryIndex', 'dasRecoveryIndex.tmp', 
    '.dasRecoveryIndex.lock', and 'dasRecoveryIndex.cor' 
    files during initialization (IZ12798).

  - There are possible buffer overflows involving 'XQUERY', 
    'XMLQUERY', 'XMLEXISTS', and 'XMLTABLE' (IZ18431).

  - There is a security vulnerability related to a 
    failure to switch the owner of the 'db2fmp' process
    affecting Unix and Linux platforms (IZ19155).

  - When a memory dump occurs, the password used to connect
    to the database remains visible in clear text in 
    memory (JR28314).

  - The CLR stored procedure deployment feature of IBM 
    Database Add-Ins for Visual Studio can be used to
    escalate privileges or launch a denial of service
    attack against a DB2 server (JR28431)." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491071/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491073/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491075/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496406/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496405/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ10776" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ10917" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ12406" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ12798" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ18431" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ19155" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR28314" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR28431" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21287889" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9.5 Fix Pack 1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
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
      is_level_older(lvl:level, base:"9.5.100.179", min:"9.5.0.0")
    ) ||
    # Linux, x86, 2.6 kernel
    (
      platform == 18 && 
      is_level_older(lvl:level, base:"9.5.0.1", min:"9.5.0.0")
    )
  ) security_hole(port);
}
