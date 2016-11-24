#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31343);
  script_version("$Revision: 1.3 $");

  script_name(english:"Netscape Browser Supported Version Detection");
  script_summary(english:"Checks if Netscape is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is no longer
supported." );
 script_set_attribute(attribute:"description", value:
"Netscape Navigator or Netscape Browser is installed on the remote
host.  Official support for all Netscape client products, including
its browser, ended as of March 1st, 2008.  As a result, the web
browser on the remote host may contain critical vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://blog.netscape.com/2007/12/28/end-of-support-for-netscape-web-browsers/" );
 script_set_attribute(attribute:"solution", value:
"Switch to another browser, such as Mozilla Firefox, which the Netscape
Team recommends." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("netscape_browser_detect.nasl");
  script_require_keys("SMB/Netscape/installed");
  exit(0);
}

#

if (get_kb_item("SMB/Netscape/installed")) 
  security_hole(get_kb_item("SMB/transport"));
