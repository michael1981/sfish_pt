#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Karol Wiesek - iDEFENSE 
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, family change (9/5/09)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(15394);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0815");
 script_bugtraq_id(11216, 11281);
 script_xref(name:"OSVDB", value:"10464");

 script_name(english:"Samba MS-DOS Path Request Arbitrary File Retrieval");

 script_set_attribute(attribute:"synopsis", value:
"The remote file server allows access to arbitrary files." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Samba server is affected
by a flaw that allows an attacker to access arbitrary files which
exist outside of the shares's defined path.  An attacker needs a valid
account to exploit this flaw." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=146" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0443.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-10/0038.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.12 / 3.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Misc.");
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.([0-9]|1[01])[^0-9]*$",string:lanman))
   security_warning(get_kb_item("SMB/transport"));
 else if(ereg(pattern:"Samba 3\.0\.([01]|2|2a)$", string:lanman))
   security_warning(get_kb_item("SMB/transport"));
}
