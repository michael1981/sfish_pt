#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21698);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-3093");
  script_bugtraq_id(18445);
  script_xref(name:"OSVDB", value:"26535");
  script_xref(name:"OSVDB", value:"26536");

  script_name(english:"Adobe Reader < 7.0.8 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks version of Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host is affected by several issues." );
 script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is earlier than 7.0.8
and thus reportedly is affected by several security issues. While details on
the nature of these flaws is currently unknown, the vendor ranks them low,
saying they have minimal impact and are difficult to exploit." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/techdocs/327817.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 7.0.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");
  exit(0);
}

#

ver = get_kb_item("SMB/Acroread/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.0\.[0-7][^0-9.]?)"
) security_warning(get_kb_item("SMB/transport"));
