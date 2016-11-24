#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29997);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0247");
  script_bugtraq_id(27235);
  script_xref(name:"OSVDB", value:"40353");

  script_name(english:"IBM Tivoli Storage Manager Express Backup Server service (dsmsvc.exe) Packet Handling Remote Overflow");
  script_summary(english:"Checks version of TSM Express");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by a buffer overflow issue." );
 script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager (TSM) Express installed on the
remote host is earlier than 5.3.7.3.  Such versions reportedly contain
a heap buffer overflow that can be triggered by a user-supplied length
value.  An unauthenticated attacker can leverage this issue to run
arbitrary code on the affected host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-001.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-01/0233.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21291536" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TSM Express 5.3.7.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("IBM/TSM/isExpress", "IBM/TSM/Version");
  script_require_ports("Services/tsm-agent");

  exit(0);
}


include("global_settings.inc");


if (!get_kb_item("IBM/TSM/isExpress")) exit(0);


port = get_kb_item("Services/tsm-agent");
if (!port) exit(0);
if (!get_port_state(port)) exit(0);


version = get_kb_item("IBM/TSM/Version");
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] == 5 && ver[1] == 3 && 
    (
      ver[2] < 7 ||
      (ver[2] == 7 && ver[3] < 3)
    )
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote host is running TSM Express version ", version, ".\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
