#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40999);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-3241", "CVE-2009-3242", "CVE-2009-3243");
  script_bugtraq_id(36408,36591);
  script_xref(name:"OSVDB", value:"58157");
  script_xref(name:"OSVDB", value:"58237");
  script_xref(name:"OSVDB", value:"58238");
  script_xref(name:"Secunia", value:"36754");

  script_name(english:"Wireshark / Ethereal 0.9.6 to 1.2.1 Multiple Vulnerabilities");
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
      "  - The GSM A RR dissector could crash. (Bug 3893)\n",
      "\n",
      "  - The OpcUa dissector could use excessive CPU and memory.\n",
      "    (Bug 3986)\n",
      "\n",
      "  - The TLS dissector could crash on some platforms.\n",
      "    (Bug 4008)\n",
      "\n",
      "  - Wireshark could crash while reading an 'ERF' file. \n",
      "    (Bug 3849)\n",
      "\n",
      "These vulnerabilities could result in a denial of service. A remote\n",
      "attacker could exploit these issues by tricking a user into opening a\n",
      "maliciously crafted capture file.  Additionally, if Wireshark is\n",
      "running in promiscuous mode, one of these issues could be exploited\n",
      "remotely (from the same network segment)."
      )
    );
    script_set_attribute(
      attribute:"see_also",
      value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3893"
    );
    script_set_attribute(
      attribute:"see_also",
      value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986"
    );
    script_set_attribute(
      attribute:"see_also",
      value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4008"
    );
    script_set_attribute(
      attribute:"see_also",
      value:"http://www.wireshark.org/security/wnpa-sec-2009-06.html"
    );
    script_set_attribute(
      attribute:"solution",
      value:"Upgrade to Wireshark version 1.2.2 or later."
    );
    script_set_attribute(
      attribute:"cvss_vector",
      value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P"
    );
    script_set_attribute(
      attribute:"vuln_publication_date",
      value:"2009/09/15"
    );
    script_set_attribute(
      attribute:"patch_publication_date",
      value:"2009/09/15"
    );
    script_set_attribute(
      attribute:"plugin_publication_date",
      value:"2009/09/16"
    );
    script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_family(english:"Windows");

    script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

    script_dependencies("wireshark_installed.nasl");
    script_require_keys("SMB/Wireshark/Installed");
    script_require_ports(139,445);

    exit(0);
}

include("global_settings.inc");

#Check each install
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, 'Unable to detect any Wireshark installs.');

info="";
foreach install(keys(installs))
{
  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Affects 0.99.6 to 1.0.8, 1.2.0 to 1.2.1.
  if (
    (
      ver[0] == 0 &&
      (
        (ver[1] == 99 && ver[2] >= 6) ||
         ver[1] > 99
      )
    ) ||
    (
      ver[0] == 1 && 
      (
        (ver[1] == 0 && ver[2] <= 8) ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  ) info += '  - Version ' + version + ', under ' + installs[install] +'\n';
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
