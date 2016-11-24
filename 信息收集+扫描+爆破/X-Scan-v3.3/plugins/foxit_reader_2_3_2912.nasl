#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32396);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-1104");
  script_bugtraq_id(29288);
  script_xref(name:"Secunia", value:"29941");
  script_xref(name:"OSVDB", value:"45351");

  script_name(english:"Foxit Reader < 2.3 Build 2912 util.printf() Function PDF File Handling Overflow");
  script_summary(english:"Checks version of Foxit Reader");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a PDF viewer that is susceptible to a
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote host reportedly
contains a boundary error triggered when parsing format strings
containing a floating point specifier in the 'util.printf()'
JavaScript function.  If an attacker can trick a user on the affected
host into opening a specially-crafted PDF file using the affected
application, he can leverage this issue to execute arbitrary code on
the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-18/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.foxitsoftware.com/bbs/announcement.php?f=3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader 2.3 Build 2923 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("SMB/Foxit_Reader/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Foxit_Reader/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 2 || 
  (
    iver[0] == 2 && 
    (
      iver[1] < 3 ||
      (iver[1] == 3 && iver[3] < 2923)
    )
  )
)
{
  if (report_verbosity)
  {
    # Report what a user would see, not what's in the KB.
    version = string(iver[0], ".", iver[1], " Build ", iver[3]);

    report = string(
      "\n",
      "Foxit Reader version ", version, " is currently installed on the\n",
      "remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
