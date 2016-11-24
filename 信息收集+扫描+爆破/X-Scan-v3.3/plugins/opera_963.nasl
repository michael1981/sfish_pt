#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35185);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-5178");
  script_bugtraq_id(32323, 32864, 32891);
  script_xref(name:"OSVDB", value:"49882");

  script_name(english:"Opera < 9.63 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 9.63
and thus reportedly affected by several issues :

  - It may be possible to execute arbitrary code on the
    remote system by manipulating certain text-area 
    contents. (920)

  - It may be possible to crash the remote browser using 
    certain HTML constructs or inject code under certain 
    conditions. (921)

  - It may be possible to trigger a buffer overflow, and
    potentially execute arbitrary code, by tricking an 
    user to click on a URL that contains exceptionally 
    long host names. (922)

  - While previewing news feeds, Opera does not correctly
    block certain scripted URLs. Such scripts, if not 
    blocked, may be able to subscribe a user to other 
    arbitrary feeds and view contents of the feeds to which
    the user is currently subscribed. (923)

  - By displaying content using XSLT as escaped strings, it 
    may be possible for a website to inject scripted
    markup. (924)" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/920" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/921" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/922" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/923" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/924" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/963/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 9.63 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

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
      ver[1]  < 63
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
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
