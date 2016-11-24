#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15860);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2004-1136");
 script_bugtraq_id(11776);
 script_xref(name:"OSVDB", value:"12241");

 script_name(english:"CuteFTP Professional FTP Command Response Remote Overflow");
 script_summary(english:"Determines the presence of CuteFTP.exe");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The FTP client installed on the remote Windows host has multiple\n",
     "buffer overflow vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host has the program CuteFTP.exe installed.\n\n",
     "CuteFTP is an FTP client which contains several buffer overflow\n",
     "conditions.  Using this version of CuteFTP to connect to a malicious\n",
     "FTP server could cause the client to crash, or could result in\n",
     "arbitrary code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-11/0394.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of CuteFTP."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencies("cuteftp_flaws.nasl");
 script_require_keys("SMB/Windows/Products/CuteFTP/Version");
 exit(0);
}

#

version = get_kb_item("SMB/Windows/Products/CuteFTP/Version");
if ( ! version ) exit(0);
if(ereg(pattern:"^([0-5]\.|6\.0\.0\.)", string:version))
  security_hole(get_kb_item("SMB/transport"));
