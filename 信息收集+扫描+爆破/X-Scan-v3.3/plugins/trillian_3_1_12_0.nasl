#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35042);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-5401", "CVE-2008-5402", "CVE-2008-5403");
  script_bugtraq_id(32645);
  script_xref(name:"Secunia", value:"33001");
  script_xref(name:"OSVDB", value:"50472");
  script_xref(name:"OSVDB", value:"50473");
  script_xref(name:"OSVDB", value:"50474");

  script_name(english:"Trillian < 3.1.12.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly
contains several vulnerabilities :

  - A stack buffer overflow in the tool tip processing code
    could allow an unauthenticated attacker to execute
    arbitrary code with client privileges on the remote 
    system. (ZDI-08-077)

  - A vulnerability in the XML processing code responsible 
    for handling specially formulated XML could lead to 
    arbitrary code execution on the remote system. 
    (ZDI-08-078)

  - A vulnerability in XML processing code responsible 
    for handling malformed XML tags could lead to 
    arbitrary code execution on the remote system.
    (ZDI-08-079)" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-077/" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-078/" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-079/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0107.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0108.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0109.html" );
 script_set_attribute(attribute:"see_also", value:"http://blog.ceruleanstudios.com/?p=404" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.12.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.([0-9]|1[01])\.))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Trillian version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
