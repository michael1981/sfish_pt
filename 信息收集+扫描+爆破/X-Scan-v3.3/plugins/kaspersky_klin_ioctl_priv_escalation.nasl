#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23996);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4926");
  script_bugtraq_id(20635);
  script_xref(name:"OSVDB", value:"29891");

  script_name(english:"Kaspersky Labs Anti-Virus IOCTL Local Privilege Escalation");
  script_summary(english:"Checks date of virus signatures");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
local privilege escalation issue." );
 script_set_attribute(attribute:"description", value:
"The version of Kaspersky Anti-Virus installed on the remote host allows
a local attacker to execute arbitrary code with kernel privileges by
passing a specially-crafted Irp structure to an IOCTL handler used by
the KLIN and KLICK device drivers.  By leveraging this flaw, a local
attacker may be able to gain complete control of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=425" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449258/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449301/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/technews?id=203038678" );
 script_set_attribute(attribute:"solution", value:
"Update the virus signatures after 10/12/2006 and restart the computer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/sigs");

  exit(0);
}


sigs = get_kb_item("Antivirus/Kaspersky/sigs");
if (sigs)
{
  sigs = split(sigs, sep:'/', keep:FALSE);
  if (
    sigs[0] == "unknown" ||
    int(sigs[2]) < 2006 || 
    (
      int(sigs[2]) == 2006 && 
      (
        int(sigs[0]) < 10 ||
        (int(sigs[0]) == 10 && int(sigs[1]) <= 12)
      )
    )
  )
  security_hole(get_kb_item("SMB/transport"));
}
