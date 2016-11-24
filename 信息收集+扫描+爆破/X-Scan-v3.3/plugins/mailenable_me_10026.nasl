#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23924);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-6605");
  script_bugtraq_id(21645);
  script_xref(name:"OSVDB", value:"32341");

  script_name(english:"MailEnable POP Server PASS Command Remote Overflow (ME-10026)");
  script_summary(english:"Checks version of MailEnable's MEPOPS.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP server is affected by a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The POP server bundled with the version of MailEnable installed on the
remote host reportedly is affected by a buffer overflow involving the
'PASS' command.  An unauthenticated remote attacker may be able to
exploit this issue to crash the service service or to execute
arbitrary code with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-75/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-12/0327.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10026." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("mailenable_detect.nasl");
  script_require_keys("SMB/MailEnable/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("misc_func.inc");


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";


# Check version of MEPOPS.exe.
if (prod == "Standard" || prod == "Professional" || prod == "Enterprise")
{
  kb_base = "SMB/MailEnable/" + prod;
  ver = read_version_in_kb(kb_base+"/MEPOPS/Version");
  if (isnull(ver)) exit(0);

  # nb: file version for MEPOPS.exe from ME-10026 is 1.0.0.27.
  if (
    ver[0] == 0 ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] == 0 && ver[3] < 27)
  )
  {
    # Let's make sure the product's version number agrees with what's reportedly affected.
    # nb: MailEnable version numbers are screwy!
    ver2 = get_kb_item(kb_base+"/Version");
    if (isnull(ver2)) exit(0);

    if (
      # 1.0-1.98 Standard Edition
      (prod == "Standard" && ver2 =~ "^1\.([0-8]($|[0-9.])|9$|9[0-8])") ||
      # 1.0-1.84 Professional Edition
      # 2.0-2.35 Professional Edition
      (prod == "Professional" && ver2 =~ "^(1\.([0-7]($|[0-9.])|8$|8[0-4])|2\.([0-2]($|[0-9.])|3($|[0-5])))") ||
      # 1.0-1.41 Enterprise Edition
      # 2.0-2.35 Enterprise Edition
      (prod == "Enterprise" && ver2 =~ "^(1\.([0-3]($|[0-9].)|4$|4[01])|2\.([0-2]($|[0-9.])|3($|[0-5])))")
    ) security_hole(get_kb_item("SMB/transport"));
  }
}
