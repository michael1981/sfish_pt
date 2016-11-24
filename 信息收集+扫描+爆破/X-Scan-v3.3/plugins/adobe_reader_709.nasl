#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24002);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046",
                "CVE-2007-0047", "CVE-2007-0048");
  script_bugtraq_id(21858, 21981);
  script_xref(name:"OSVDB", value:"31046");
  script_xref(name:"OSVDB", value:"31047");
  script_xref(name:"OSVDB", value:"31048");
  script_xref(name:"OSVDB", value:"31316");
  script_xref(name:"OSVDB", value:"31596");
  script_xref(name:"OSVDB", value:"34407");

  script_name(english:"Adobe Reader < 6.0.6 / 7.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by several
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier
than 7.0.9 / 8.0 and thus reportedly is affected by several security
issues, including one that can lead to arbitrary code execution when
processing a malicious PDF file." );
 script_set_attribute(attribute:"see_also", value:"http://www.piotrbania.com/all/adv/adobe-acrobat-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0200.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 6.0.6 / 7.0.9 / 8.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

#

ver = get_kb_item("SMB/Acroread/Version");
if (
  ver && 
  ver =~ "^([0-5]\.|6\.0\.[0-5][^0-9.]?|7\.0\.[0-8][^0-9.]?)"
) security_hole(get_kb_item("SMB/transport"));
