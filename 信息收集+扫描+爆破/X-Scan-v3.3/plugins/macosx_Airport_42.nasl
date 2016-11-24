#TRUSTED 1bf5945ffd33a275814a31dd4870940411a6ac34704362db96bcc241413a8aab316062dd40d50c283c7514dda24aee61b06a1dcaca8d58a0e4fd745c6d359dff83b4d4cb2e9c1f7457d06a0dd4ecc901a9678d099151a13bf83fd14769129472d590a356ccccc4d8240e3f0a482a650d92080935b781ae385db085d34fc58ba1ddd7468fd650dc2fc429563c92c932d490dbb23ce8d4bc7dfae3b36ee5c7d57846a37c5f11d0e20ec78364401d3895c0fa5679f8545261b8735b992ef63ef3645ef15f1cd882ece68608631319de67b9e2362d6bb70e69a6590048e0cb14930bc4dc7fc93c1b9f6aed52ae6be2e7dd766cbac268d01c09b39b327fce64d6b206c6c2bd5303dd1d115688eb44614153c8b6cd1b4920658d170c5eb47cbb01a25c59e9028621854d91a086bab99b704b38a6531a167099ee72cb0f3ebb5950f790fa135ff330d92233acf66cc90401ed33d86227f745ab4f56460ed70ca0e15323cd22dc88af4bf20323d1ac127462a755440c638bb9e98809ddcd1d4dc1842d1bfe6bd648349f81bae435288691e6acbea94a1aea584ab358612d805dd06d8d9f6d962060cc11cd3feaf85750b31d1aaf86cc73e2b3bbf2fdc4433619fe1af83c5eb9514b87257ed1b5cd381af41afca4b4b415a1043a069466ba0c13d23ed2624acd3d0e8d8c48075894dff5527330a5e8315a1b0e0fb1d82adaf9bf0eba251e
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19295);
 script_version ("1.7");

 script_cve_id("CVE-2005-2196");
 script_bugtraq_id(14321);
 script_xref(name:"OSVDB", value:"18085");

 script_name(english:"Airport < 4.2");
 script_summary(english:"Check for the version of Mac OS X");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is missing a Mac OS X update that fixes a security\n",
     "issue."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of Mac OS X which contains an\n",
     "Airport driver with an automatic network association vulnerability,\n",
     "that may cause a computer to connect to potentially malicious\n",
     "networks without notifying the end-user."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA23400"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Airport 4.2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2005/07/25"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
 script_dependencies("ssh_get_info.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) exit(0);

cmd = GetBundleVersionCmd(file:"AirPort Admin Utility.app", path:"/Applications/Utilities");

if ( !ereg(pattern:"Mac OS X 10\.(3|4\.[012]([^0-9]|$))", string:os) ) exit(0);

if ( islocalhost() )
{
 buf = pread(cmd:"grep", argv:make_list("bash", "-c", cmd));
}
else 
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}


if ( buf && ereg(pattern:"^([0-3]\.|4\.[01](\..*)?)", string:buf) ) security_warning(0);
