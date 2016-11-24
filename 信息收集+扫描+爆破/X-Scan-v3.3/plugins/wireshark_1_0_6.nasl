#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35629);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0599", "CVE-2009-0600");
  script_bugtraq_id(33690);
  script_xref(name:"OSVDB", value:"51815");
  script_xref(name:"OSVDB", value:"51987");
  script_xref(name:"Secunia", value:"33872");

  script_name(english:"Wireshark / Ethereal 0.99.6 to 1.0.5 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks Wireshark / Ethereal version"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is susceptible to multiple
denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by multiple
denial of service issues :

  - Wireshark could crash while reading a malformed NetScreen
    snoop file. (Bug 3151)

  - Wireshark could crash while reading a Tektronix K12 
    text capture file. (Bug 1937)" );
 script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3151" );
 script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1937" );
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2009-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/news/20090206.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark 1.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P" );
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
if (isnull(installs)) exit(0);

info = "";
foreach install (keys(installs))
{
  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    v[i] = int(ver[i]);

  if (
    (
      ver[0] == 0 && 
      (
        (ver[1] == 99 && ver[2] >= 6) ||
        ver[1] > 99
      )
    ) ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] < 6)
  ) info += '  - Version ' + version + ', under ' + installs[install] + '\n';
}


# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s of Wireshark / Ethereal are";
    else s = " of Wireshark or Ethereal is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the\n",
      "remote host :\n",
      "\n",
      info
    );
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
