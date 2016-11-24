#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27583);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4277");
  script_bugtraq_id(26209);
  script_xref(name:"OSVDB", value:"39755");

  script_name(english:"Trend Micro Scan Engine Tmxpflt.sys Buffer Overflow");
  script_summary(english:"Checks version of AV scan engine");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a local
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Trend Micro AntiVirus installed on the remote Windows
host contains a buffer overflow in its 'Tmxpflt.sys' kernel driver.  A
local attacker may be able to leverage this issue to execute arbitrary
code on the affected system in kernel context." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=609" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482794/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/support/viewxml.do?ContentID=1036190" );
 script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/support/viewxml.do?ContentID=1035793" );
 script_set_attribute(attribute:"solution", value:
"Update to Scan Engine 8.550-1001 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/installed", "Antivirus/TrendMicro/trendmicro_engine_version");

  exit(0);
}


engine = get_kb_item("Antivirus/TrendMicro/trendmicro_engine_version");
if (!engine) exit(0);


# 8550 => version 8.550
if (int(engine) < 8550) security_warning(get_kb_item("SMB/transport"));
