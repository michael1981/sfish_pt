#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10866);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2002-0057");
 script_bugtraq_id(3699);
 script_xref(name:"OSVDB", value:"3032");
 
 script_name(english:"MS02-008: XML Core Services patch (318203)");
 script_summary(english:"Determines whether the XML Core Services patch Q318202/Q318203 is installed");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"Local files can be retrieved through the web client."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Internet Explorer that may\n",
   "allow an attacker to read local files on the remote host. \n",
   "\n",
   "To exploit this flaw, an attacker would need to lure a victim on the\n",
   "remote system into visiting a rogue website."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for the Windows NT, 2000 and\n",
   "XP :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms02-008.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#deprecated -> FP
exit(0);
