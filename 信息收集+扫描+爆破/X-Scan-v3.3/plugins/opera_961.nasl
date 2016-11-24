#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34459);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4725");
  script_bugtraq_id(31842, 31869);
  script_xref(name:"OSVDB", value:"49738");
  script_xref(name:"OSVDB", value:"49739");
  script_xref(name:"OSVDB", value:"49740");
  script_xref(name:"OSVDB", value:"49741");
  script_xref(name:"Secunia", value:"32299");
  
  script_name(english:"Opera < 9.61 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.61
and thus reportedly affected by several issues :

  - It may be possible to reveal a user's browsing history 
    by exploiting certain constructs in Opera's History
    Search results (903).
  
  - Opera's Fast Forward feature is affected by a cross-site
    scripting vulnerability (904). 

  - While previewing certain news feeds, it may be possible 
    for certain scripts to subscribe an user to arbitrary 
    feeds, and also view contents of user subscribed feeds 
    (905)." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/903/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/904/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/905/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/961/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.61 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 || 
  (
    ver[0] == 9 && 
    (
      ver[1]  < 61
    )
  )
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
