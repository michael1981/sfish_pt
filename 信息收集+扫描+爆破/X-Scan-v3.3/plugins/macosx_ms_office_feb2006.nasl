#TRUSTED a85ad2f5f0982951dedb1f0e3829b9d28c4a4763d8b64ee850db23248dccf15606a43a6521c27a77ff92a5bcbf46d08e13fa303651bc53c8916e82f24635cbffaba60d6f489d81c7d4e4d3e30dcff8c0bd437f0683f927ecdb1e81277b00280714326dc742a7c0f98fb66d75110a762e25287e6d4894241ebb4f2839aa734ff3f6e2a91de622819b42a25fae21a2926e84b2c064ec2807a0254ff77316eb583bbdac60bf7b65ff42e966c5576978e3d6f33313b18d2236b5cdd76b14cd2b2c5f86d5ba829295dfe8b6718143d097ae0b784ad51d977c421aefe7d47ecab41e7d107ed45165149b542b9d472fdba3890c6ec58e20bd62ea7803b30fc60c11668cd4a86793ebe34e2cf4a365b11819962abf4eb672b82d87333125e4289d9d3e8e8f99e2ae00016ab5253722d681e165a5877a3221353862402dc20fdad05e0ae3c7d9c158fc3788c77d5670b8cc8f968aa60e9d7587bf2cb1e5988e3035a7bab67c4e68ce1d4582cf4473b55aeebdcceed20968d9a49a169f84b8744d24f3652630ac1357d127399dd2f04d3e991316401ed69ac9be3f7d0d5c92259c6d8f3f60213610aa454974b2b8fadef67ab06bebddec559bf92b506b210d842dc6793e490a0e9c23a69d07a6ab6529ddefb8e08d2605aeca764121824f81c2a97dd5c6564824201bad992ea2ab25c4f4c65ae59d19794291b46e120f37bb23952d52b058
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);
if (!defined_func("bn_random")) exit(0);

include("compat.inc");


if(description)
{
 script_id(24328);
 script_version ("1.6");

 script_cve_id(
  "CVE-2006-3877", 
  "CVE-2006-5994", 
  "CVE-2006-6456", 
  "CVE-2006-6561", 
  "CVE-2007-0208", 
  "CVE-2007-0209", 
  "CVE-2007-0515",
  "CVE-2007-0671" 
 );
 script_bugtraq_id(20325, 21451, 21518, 21589, 22225, 22383, 22477, 22482);
 script_xref(name:"OSVDB", value:"29448");
 script_xref(name:"OSVDB", value:"30824");
 script_xref(name:"OSVDB", value:"30825");
 script_xref(name:"OSVDB", value:"31900");
 script_xref(name:"OSVDB", value:"31901");
 script_xref(name:"OSVDB", value:"33270");
 script_xref(name:"OSVDB", value:"34385");
 script_xref(name:"OSVDB", value:"34386");
 
 script_name(english:"MS07-014 / MS07-015: Vulnerabilities in Microsoft Word and Office Could Allow Remote Code Execution (929434 / 932554) (Mac OS X)");
 script_summary(english:"Checks version of Word 2004");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host through Microsoft\n",
   "Office."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft Office that is\n",
   "affected by various flaws that may allow arbitrary code to be run. \n",
   "\n",
   "To succeed, the attacker would have to send a rogue file to a user of\n",
   "the remote computer and have it open it with Microsoft Word or another\n",
   "Office application."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Office for Mac OS X :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms07-014.mspx\n",
   "http://www.microsoft.com/technet/security/bulletin/ms07-015.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = GetCarbonVersionCmd(file:"Microsoft Word", path:"/Applications/Microsoft Office 2004");
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   ssh_close_connection();
  }
  else
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", off2004));


 if ( buf =~ "^11\." )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
          # < 11.3.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 3  || ( int(vers[1]) == 3 && int(vers[2]) < 4 ) ) ) security_hole(0);
	} 
}
