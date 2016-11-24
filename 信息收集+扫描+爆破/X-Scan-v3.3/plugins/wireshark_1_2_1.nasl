#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40335);
  script_version("$Revision: 1.5 $");

  script_cve_id(
    "CVE-2009-2559",
    "CVE-2009-2560",
    "CVE-2009-2561",
    "CVE-2009-2562",
    "CVE-2009-2563"
  );
  script_bugtraq_id(35748);
  script_xref(name:"OSVDB", value:"56016");
  script_xref(name:"OSVDB", value:"56017");
  script_xref(name:"OSVDB", value:"56018");
  script_xref(name:"OSVDB", value:"56019");
  script_xref(name:"OSVDB", value:"56020");
  script_xref(name:"OSVDB", value:"56021");
  script_xref(name:"OSVDB", value:"56022");
  script_xref(name:"Secunia", value:"35884");

  script_name(english:"Wireshark / Ethereal 0.9.2 to 1.2.0 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has an application that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The installed version of Wireshark or Ethereal is affected by\n",
      "multiple issues :\n",
      "\n",
      "  - The IPMI dissector could overrun a buffer. (Bug 3559)\n",
      "\n",
      "  - The AFS dissector could crash. (Bug 3564)\n",
      "\n",
      "  - The Infiniband dissector could crash on some platforms.\n",
      "\n",
      "  - The Bluetooth L2CAP dissector could crash. (Bug 3572)\n",
      "\n",
      "  - The RADIUS dissector could crash. (Bug 3578)\n",
      "\n",
      "  - The MIOP dissector could crash. (Bug 3652)\n",
      "\n",
      "  - The sFlow dissector could use excessive CPU and memory.\n",
      "    (Bug 3570)\n",
      "\n",
      "These vulnerabilities could result in a denial of service, or\n",
      "possibly arbitrary code execution.  A remote attacker could exploit\n",
      "these issues by tricking a user into opening a maliciously crafted\n",
      "capture file.  Additionally, if Wireshark is running in promiscuous\n",
      "mode, one of these issues could be exploited remotely (from the same\n",
      "network segment)."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-04.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");
  script_require_ports(139, 445);
  
  exit(0);
}

include("global_settings.inc");

# Check each install.
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, 'Unable to detect any Wireshark installs.');

info = "";
foreach install(keys(installs))
{
  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Affects 0.9.2 to 1.2.0 inclusive
  if (
    (
      ver[0] == 0 &&
      (
        (ver[1] == 9 && ver[2] >= 2) ||
        ver[1] > 9
      )
    ) ||
    (ver[0] == 1 &&
     (ver[1] < 2 || (ver[1] == 2 && ver[2] == 0)))
  ) info += '  - Version ' + version + ', under ' + installs[install] + '\n';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s of Wireshark / Ethereal are";
    else s = " of Wireshark / Ethereal is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
