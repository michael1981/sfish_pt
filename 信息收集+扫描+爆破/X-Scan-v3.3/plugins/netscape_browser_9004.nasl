#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(28377);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_xref(name:"OSVDB", value:"38463");
  script_xref(name:"OSVDB", value:"38867");
  script_xref(name:"OSVDB", value:"38868");

  script_name(english:"Netscape Browser < 9.0.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Netscape");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Netscape is affected by various security
issues :

  - Three bugs that can result in crashes with traces 
    of memory corruption

  - A cross-site scripting vulnerability involving
    support for the 'jar:' URI scheme

  - A timing issue when setting the 'window.location' 
    property that could be leveraged to conduct
    cross-site request forgery attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-39.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8800503" );
 script_set_attribute(attribute:"see_also", value:"http://blog.netscape.com/2007/12/28/end-of-support-for-netscape-web-browsers/" );
 script_set_attribute(attribute:"solution", value:
"The Netscape Browser / Navigator has been discontinued.  While these
issues were reportedly fixed in 9.0.0.4, it is strongly recommended
that you switch to the latest version of another browser, such as
Mozilla Firefox, which the Netscape Team recommends." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("netscape_browser_detect.nasl");
  script_require_keys("SMB/Netscape/installed");
  exit(0);
}

#

list = get_kb_list("SMB/Netscape/*");
if (isnull(list)) exit(0);

foreach key (keys(list))
{
  ver = key - "SMB/Netscape/";
  if (ver && ver =~ "^([0-8]\.|9\.0($|\.0\.[0-3]))")
  {
    security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
}
