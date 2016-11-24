#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25932);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4391");
  script_bugtraq_id(25330);
  script_xref(name:"OSVDB", value:"38221");

  script_name(english:"Yahoo! Messenger < 8.1.0.416 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Yahoo! Messenger"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The instant messaging application on the remote Windows host is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Yahoo! Messenger installed on the remote host is
reportedly affected by a buffer overflow as well as a denial of
service vulnerability, both involving its video chat feature. 

If an attacker can trick a user on the affected host into accepting a
webcam invitation, he may be able to leverage these issues to crash
the affected application or execute arbitrary code on the host subject
to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://messenger.yahoo.com/security_update.php?id=082107" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Yahoo! Messenger version 8.1.0.416 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("yahoo_installed.nasl");
  script_require_keys("SMB/Yahoo/Messenger/Version");

  exit(0);
}


ver = get_kb_item("SMB/Yahoo/Messenger/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix = split("8.1.0.416", sep:'.', keep:FALSE);
for (i=0; i<4; i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    report = string(
      "Version ", ver, " of Yahoo! Messenger is currently installed on\n",
      "the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra: report);
    break;
  }
  else if (iver[i] > fix[i])
    break;
