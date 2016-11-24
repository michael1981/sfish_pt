#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32400);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-2407", "CVE-2008-2408", "CVE-2008-2409");
  script_bugtraq_id(29330);
  script_xref(name:"OSVDB", value:"45681");
  script_xref(name:"OSVDB", value:"45682");
  script_xref(name:"OSVDB", value:"45683");
  script_xref(name:"Secunia", value:"30336");

  script_name(english:"Trillian < 3.1.10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly
contains several vulnerabilities :

  - A stack buffer overflow in 'aim.dll' triggered when
    parsing messages with overly long attribute values
    within the 'FONT' tag.

  - A memory corruption issue within XML parsing in
    'talk.dll' triggered when processing malformed
    attributes within an 'IMG' tag. 

  - A stack buffer overflow in the header-parsing code
    for the MSN protocol when processing the 
    'X-MMS-IM-FORMAT' header.

Successful exploitation of each issue can result in code execution
subject to the privileges of the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-029" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-030" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-031" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0554.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0555.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-05/0556.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.10.0 or later as it is reported to resolve
these issues." );
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
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-9]\.))")
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
