#TRUSTED 680ab9b0205d6bbc168471f5aa0efb877dace1d15bfc5afc5c3a6403aa21d9dd200333a406b2a7ae4e96684c877a67382ba4f00c1694121bac4416529da05e2d5eb769cf1a62d893d10c3e14ddd2a8f365c5b514b23e12dd19bd325736d045b184b10b69352db6cf33c937605c789e024a39f5cd9547cd76b8ac4bc810ab69e463e8c77209c05d03f1d61bab82ce6472de7ebaad34a0398f760c37eb04dea29e164bf683c8a78c6fc42980d32c06d5aed899d1b6dafeea968882b3e68706e8daaac8ae2e9b92ce10f1a0ceae72f495c22b83ad0e580fac0c1ddbdaf067a7000648790c8dfff73c49a4807e2d0a6f2531cbc846c5bb1b6064eec13acc0177bf7d80a8b06ba07f73be9b36fcdf0b353de40982256c1fc347d8555cf96889f36c413060de618fb311cd47ce50be5eff21e0d8b8eb0f8c7287488669b5abe973d9d2ddbbb57fc6ef13164db16c958d098f0ca7f8cd1638d907f6f19e804aa1908d88f9e8b662d7828be748e65f8ff38c81915d433118e3900aa6bf62dcd00274c80a0c285e1d21096033c82b5a14701af675368d9fcb7000e08760c7da94aabe9f114aa46f28a77224161e9c449885e1e77bfe5ca2f07205e809e7e08fd1863f538b4cd8bf741265b8841bbd018c099c37a162629c45b10d3dcdd3f8a766d4adc8448602d219d90be4b9525e741512788b8bd141dae598ebf8202f919f99043a4f38
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16151);
 script_version ("1.10");

 script_cve_id("CVE-2005-0043");
 script_bugtraq_id(12238);
 script_xref(name:"OSVDB", value:"12833");
 script_xref(name:"Secunia", value:"13804");

 script_name(english:"iTunes < 4.7.1");
 script_summary(english:"Check the version of iTunes");

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
     "The remote host is running a version of iTunes which is older than\n",
     "version 4.7.1.  The remote version of this software is vulnerable\n",
     "to a buffer overflow when it parses a malformed playlist file\n",
     "(.m3u or .pls files).  A remote attacker could exploit this by\n",
     "tricking a user into opening a maliciously crafted file, resulting\n",
     "in arbitrary code execution."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0154.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0172.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?eba3be11 (Apple advisory)"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to iTunes 4.7.1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute( 
  attribute:"plugin_publication_date",  
  value:"2005/01/13"
 ); 
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("ssh_func.inc");
include("macosx_func.inc");

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");

if ( islocalhost() )
 buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
else 
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( ! buf ) exit(0);
if ( ! ereg(pattern:"^iTunes [0-9.]", string:buf) ) exit(0);
version = ereg_replace(pattern:"^iTunes ([0-9.]+),.*", string:buf, replace:"\1");
set_kb_item(name:"iTunes/Version", value:version);
if ( egrep(pattern:"iTunes 4\.([0-6]\..*|7|7\.0)$", string:buf) ) security_warning(0); 
