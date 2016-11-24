#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40549);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2714", "CVE-2009-2715");
  script_bugtraq_id(35915, 35960);
  script_xref(name:"OSVDB", value:"56810");
  script_xref(name:"OSVDB", value:"56893");
  script_xref(name:"Secunia", value:"36080");
  script_xref(name:"milw0rm", value:"9323");

  script_name(english:"Sun xVM VirtualBox < 3.0.4 Multiple Local Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check on VirtualBox.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host has an application that is affected by\n",
      "local denial of service vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host contains a version of Sun xVM VirtualBox, an open\n",
      "source virtualization platform, before 3.0.4.  Such versions\n",
      "have multiple local denial of service vulnerabilities.  A guest\n",
      "virtual machine (VM) can reboot the host machine by executing the\n",
      "'sysenter' instruction.  The vendor states there are several other\n",
      "denial of service vulnerabilities in addition to this.\n\n",
      "An attacker with access to the guest VM could leverage these to\n",
      "cause a denial of service."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-265268-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://forums.virtualbox.org/viewtopic.php?f=1&t=20948"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Sun xVM VirtualBox 3.0.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/08/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


ver = get_kb_item('VirtualBox/Version');
if (isnull(ver)) exit(1, "The 'VirtualBox/Version' KB item is missing.");

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 3.0.4 are affected
if (
  major < 3 ||
  major == 3 && minor == 0 && rev < 4
)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Product version    : ", ver, "\n",
      "  Should be at least : 3.0.4\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + ver + " is not affected.");
