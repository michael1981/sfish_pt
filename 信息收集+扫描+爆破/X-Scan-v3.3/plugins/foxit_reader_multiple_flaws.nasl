#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35807);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0191", "CVE-2009-0836", "CVE-2009-0837");
  script_bugtraq_id(34035);
  script_xref(name:"OSVDB", value:"55614");
  script_xref(name:"OSVDB", value:"55615");
  script_xref(name:"OSVDB", value:"55616");
  script_xref(name:"Secunia", value:"34036");

  script_name(english:"Foxit Reader < 3.0 Build 1506 / 2.3 Build 3902 Multiple Flaws");
  script_summary(english:"Checks version of Foxit Reader");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a PDF viewer that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote host is affected
by multiple flaws :

  - If an action in a PDF file requires opening a file
    or web link with very long file names and it satisfies
    a trigger condition specific to Foxit Reader, it might 
    be possible to trigger a stack based buffer overflow
    condition. This flaw only affects Foxit Reader version
    3.0.

  - If an action defined in a PDF document matches certain 
    trigger conditions specific to Foxit Reader, it may be 
    possible to bypass the authorization required to execute 
    that action.

  - By using a specially crafted PDF file designed to 
    exploit an error in JBIG2 symbol dictionary segments, 
    it may be possible to dereference an uninitialized 
    location in the memory. Successful exploitation of
    this issue could result in arbitrary code execution
    on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-11/" );
 script_set_attribute(attribute:"see_also", value:"http://www.foxitsoftware.com/pdf/reader/security.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader 3.0 Build 1506/2.3 Build 3902 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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

if(
  (iver[0] == 2 && iver[1] == 3 && iver[3] < 3902) ||
  (iver[0] == 3 && iver[1] == 0 && iver[3] < 1506)
)
{
  if (report_verbosity > 0)
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
