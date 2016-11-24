#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23756);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-6290", "CVE-2006-6291");
  script_bugtraq_id(21362);
  script_xref(name:"OSVDB", value:"30661");
  script_xref(name:"OSVDB", value:"31698");
  script_xref(name:"OSVDB", value:"31699");
  script_xref(name:"Secunia", value:"23080");

  script_name(english:"MailEnable IMAP Server Multiple Buffer Overflow Vulnerabilities (ME-10021)");
  script_summary(english:"Checks version of MailEnable's MEIMAPS.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The IMAP server bundled with the version of MailEnable installed on
the remote host reportedly fails to handle malicious arguments to the
'EXAMINE', 'SELECT', and 'DELETE' commands.  An authenticated remote
attacker may be able to exploit these issues to crash the affected
service or to execute arbitrary code with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-71/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0535.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
 script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10021. 

Note that ME-10020 was initially listed as a solution, but it turns
out to be only a partial fix.  Affected users should apply ME-10021 to
fully address the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C" );
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


# Check version of MEIMAPS.exe.
if (prod == "Professional" || prod == "Enterprise")
{
  kb_base = "SMB/MailEnable/" + prod;
  ver = read_version_in_kb(kb_base+"/MEIMAPS/Version");
  if (isnull(ver)) exit(0);

  # nb: file version for MEIMAPS.exe from ME-10021 is 1.0.0.26.
  if (
    ver[0] == 0 ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] == 0 && ver[3] < 26)
  )
  {
    # Let's make sure the product's version number agrees with what's reportedly affected.
    # nb: MailEnable version numbers are screwy!
    ver2 = get_kb_item(kb_base+"/Version");
    if (isnull(ver2)) exit(0);

    if (
      # 1.6-1.83 Professional Edition
      # 2.0-2.33 Professional Edition
      (prod == "Professional" && ver2 =~ "^(1\.([67]($|[0-9.])|8$|8[0-3])|2\.([0-2]($|[0-9.])|3($|[0-3])))") ||
      # 1.1-1.40 Enterprise Edition
      # 2.0-2.33 Enterprise Edition
      (prod == "Enterprise" && ver2 =~ "^(1\.([1-3]($|[0-9].)|4$)|2\.([0-2]($|[0-9.])|3($|[0-3])))")
    ) security_warning(get_kb_item("SMB/transport"));
  }
}
