#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40871);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-3037");
  script_bugtraq_id(36042);
  script_xref(name:"OSVDB", value:"57334");
  script_xref(name:"Secunia", value:"36421");

  script_name(english:"Symantec Mail Security For SMTP KeyView Excel SST Parsing Integer Overflow");
  script_summary(english:"Does a version check on SMSSMTP");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The email security application running on the remote Windows host has\n",
      "an integer overflow vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Symantec Mail Security for SMTP running on the remote\n",
      "host has an integer overflow vulnerability when parsing a Shared\n",
      "String Table (SST) record inside of an Excel file.  One of the fields\n",
      "in the SST is a 32-bit integer used to specify the size of a dynamic\n",
      "memory allocation.  This integer is not validated, which could result\n",
      "in a heap buffer overflow.\n",
      "\n",
      "A remote attacker could exploit this by tricking a user into viewing\n",
      "an email with a maliciously crafted Excel file, which could lead to\n",
      "execution of arbitrary code as SYSTEM."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e25c6dae (Symantec advisory)"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply patch level 205."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/25"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/25"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/04"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("sms_smtp_installed.nasl");
  script_require_keys("Symantec/SMSSMTP/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


ver = get_kb_item('Symantec/SMSSMTP/Version');
if (isnull(ver)) exit(1, "The 'Symantec/SMSSMTP/Version' KB item is missing.");

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);

# Only the 5.0.x branch is affected
if (major != 5 && minor != 0) exit(0, "Version "+ver+" is not affected.");

path_key = 'SMB/Symantec/SMSSMTP/' + ver;
path = get_kb_item(path_key);
if (isnull(path)) exit(1, "The '"+path_key+"' KB item is missing.");

dll_path = path + "\scanner\rules\verity";
dll_file = "xlssr.dll";

res = hotfix_check_fversion(file:dll_file, version:"10.4.0.0", path:dll_path);

# After a vanilla install, there is no version in the metadata of the affected
# file
if (res == HCF_OLDER || res == HCF_NOVER)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
if (res != HCF_OK) exit(1, "Unable to do version check (error code: " + res + ").");
else exit(0, "The system is not affected.");
