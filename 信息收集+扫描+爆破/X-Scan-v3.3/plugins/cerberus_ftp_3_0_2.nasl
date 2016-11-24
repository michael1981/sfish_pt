#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40821);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(36134);
  script_xref(name:"Secunia", value:"36456");
  script_xref(name:"Milw0rm", value:"9515");

  script_name(english:"Cerberus FTP Server Command Processing DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The FTP server installed on the remote Windows host has a denial of\n",
      "service vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Cerberus FTP server on the remote host has a denial of\n",
      "service vulnerability.  Sending a very long argument (1400 bytes or\n",
      "more) to any command causes the server to crash.  This reportedly\n",
      "does not result in memory corruption - the vulnerable versions\n",
      "abnormally terminate when a long argument is received (before any\n",
      "data is successfully copied into the destination buffer).  A remote\n",
      "attacker could exploit this issue to cause a denial of service."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cerberusftp.com/phpBB3/viewtopic.php?f=4&t=2411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cerberusftp.com/releasenotes.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cerberus FTP server 3.0.2 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/12"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/16"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/31"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("cerberus_ftp_installed.nasl");
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");


ver = get_kb_item('CerberusFTP/Version');
if (isnull(ver)) exit(1, "Cerberus FTP was not detected on this host.");

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Testing indicates this doesn't affect the 2.x branch. Version 3.0.0 is likely
# affected, and 3.0.1 is definitely affected (per the developer) 
if (major == 3 && minor == 0 && rev < 2)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Product version    : ", ver, "\n",
      "  Should be at least : 3.0.2\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + ver + " is not affected.");

