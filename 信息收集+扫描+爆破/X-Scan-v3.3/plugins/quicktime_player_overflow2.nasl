#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20136);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2005-2753", "CVE-2005-2754", "CVE-2005-2755", "CVE-2005-2756");
 script_bugtraq_id(15306, 15307, 15308, 15309);
 script_xref(name:"OSVDB", value:"20475");
 script_xref(name:"OSVDB", value:"20476");
 script_xref(name:"OSVDB", value:"20477");
 script_xref(name:"OSVDB", value:"20478");

 script_name(english:"QuickTime < 7.0.3 Multiple Vulnerabilities (Windows)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime may allow an attacker to execute
arbitrary code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of QuickTime that is
older than QuickTime 7.0.3. 

The remote version of this software is reportedly vulnerable to
various buffer overflows that may allow an attacker to execute
arbitrary code on the remote host by sending a malformed file to a
victim and have him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=302772" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime 7.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check for QuickTime < 7.0.3");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");
 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.[0-2])") security_hole(get_kb_item("SMB/transport"));
