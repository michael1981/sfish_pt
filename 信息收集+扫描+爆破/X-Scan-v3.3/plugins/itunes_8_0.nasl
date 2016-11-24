#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34157);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-3636");
  script_bugtraq_id(31089);
  script_xref(name:"OSVDB", value:"48009");

  script_name(english:"iTunes < 8.0 Integer Buffer Overflow (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
integer buffer vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of iTunes installed on the remote Windows host is older
than 8.0.  Such versions include a third-party driver that are
affected by an integer buffer overflow that could allow a local user
to gain system privileges." );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3025" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 8.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 8)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "iTunes ", version, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
